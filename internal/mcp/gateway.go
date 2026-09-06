package mcp

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"time"

	"sentinel/internal/audit"
	"sentinel/internal/placeholder"
	"sentinel/internal/policy"
	"sentinel/internal/scrubber"
	"sentinel/internal/vault"
)

// Mode controls secret handling in stdio run:
//   - "inject": resolve snt:// placeholders in env to real values for child.
//   - "proxy": leave placeholders; child traffic must go via egress proxy.
const (
	ModeInject = "inject"
	ModeProxy  = "proxy"
)

// MaxFrameSize caps a single frame. 10 MiB frames are rejected, not buffered.
const MaxFrameSize = 10 * 1024 * 1024

// Framing is the peer framing detected once per stream.
type Framing int

const (
	FramingLine Framing = iota
	FramingContentLength
)

// FrameError is a named error for framing failures.
type FrameError struct {
	Kind    string // "truncated" | "too_large" | "malformed_header" | "eof"
	Message string
	Err     error
}

func (e *FrameError) Error() string {
	if e.Err != nil {
		return fmt.Sprintf("mcp frame %s: %s: %v", e.Kind, e.Message, e.Err)
	}
	return fmt.Sprintf("mcp frame %s: %s", e.Kind, e.Message)
}

func (e *FrameError) Unwrap() error { return e.Err }

// SkipFields documents protocol fields where redaction would break JSON-RPC/MCP.
// Scrub walks every string leaf by JSON shape except these skipped keys/paths.
var SkipFields = map[string]bool{
	"jsonrpc": true,
	"id":      true,
	"method":  true,
	"uri":     true,
	// JSON-schema structural fields where rewriting breaks validation:
	"$schema":              true,
	"$ref":                 true,
	"type":                 true,
	"required":             true,
	"properties":           true,
	"additionalProperties": true,
	"enum":                 true,
}

// RunWithMode is Run with explicit mode. Empty mode defaults to inject.
func RunWithMode(args []string, mode string, st *vault.Store, p *policy.Policy, l *audit.Logger, sess *scrubber.Session) error {
	if mode == "" {
		mode = ModeInject
	}
	if mode != ModeInject && mode != ModeProxy {
		return fmt.Errorf("invalid mode %q: want inject|proxy", mode)
	}
	return runInner(args, mode, st, p, l, sess)
}

// Run wraps an MCP stdio server: resolves snt:// in env for child,
// scrubs tool results to LLM, blocks foreign placeholders in tool args.
func Run(args []string, st *vault.Store, p *policy.Policy, l *audit.Logger, sess *scrubber.Session) error {
	return runInner(args, ModeInject, st, p, l, sess)
}

func runInner(args []string, mode string, st *vault.Store, p *policy.Policy, l *audit.Logger, sess *scrubber.Session) error {
	i := 0
	for i < len(args) && args[i] != "--" {
		i++
	}
	profile := ""
	for j := 0; j+1 < i; j++ {
		if args[j] == "--profile" {
			profile = args[j+1]
		}
	}
	if i < len(args) && args[i] == "--" {
		i++
	}
	if i >= len(args) {
		return fmt.Errorf("usage: sentinel mcp run [--profile NAME] -- <cmd...>")
	}
	thr := p.Defaults.ConfidenceThreshold
	if thr == 0 {
		thr = 0.7
	}
	scrubMode := p.Defaults.ScrubToLLM
	if scrubMode == "" {
		scrubMode = "pseudonymize"
	}
	allow := map[string]bool{}
	for _, v := range p.Allowlist.Values {
		allow[v] = true
	}
	deny := map[string]bool{}
	_ = profile
	if profile != "" {
		for k := range p.Entities {
			if strings.HasPrefix(k, "mcp:deny:") {
				deny[strings.TrimPrefix(k, "mcp:deny:")] = true
			}
		}
	}

	env := os.Environ()
	if mode == ModeInject {
		for idx, kv := range env {
			if parts := strings.SplitN(kv, "=", 2); len(parts) == 2 {
				resolved := parts[1]
				changed := false
				for _, ph := range placeholder.Find(parts[1]) {
					name := strings.TrimPrefix(ph, "snt://")
					sec, err := st.Get(name)
					if err != nil {
						continue
					}
					resolved = strings.ReplaceAll(resolved, ph, string(sec.Value))
					zero(sec.Value)
					changed = true
				}
				if changed {
					env[idx] = parts[0] + "=" + resolved
				}
			}
		}
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	c := exec.CommandContext(ctx, args[i], args[i+1:]...)
	c.Env = env
	stdin, _ := c.StdinPipe()
	stdout, _ := c.StdoutPipe()
	stderrPipe, _ := c.StderrPipe()
	if err := c.Start(); err != nil {
		return err
	}
	emit := func(typ string, f map[string]any) {
		if l != nil {
			l.Log("", typ, f)
		}
	}

	var vm vault.Matcher
	if st != nil {
		if m, err := st.NewMatcher(); err == nil {
			vm = m
			defer m.Close()
		}
	}

	// Detect peer framing once from stdin, respond in the same framing.
	peerFraming := detectPeerFraming()
	respMu := sync.Mutex{}
	writeResp := func(payload string) {
		respMu.Lock()
		defer respMu.Unlock()
		if peerFraming == FramingContentLength {
			fmt.Fprintf(os.Stdout, "Content-Length: %d\r\n\r\n%s", len(payload), payload)
		} else {
			os.Stdout.Write([]byte(payload + "\n"))
		}
	}
	writeErrID := func(id any, reason string) {
		b, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": id, "error": map[string]any{"code": -32602, "message": "sentinel: " + reason}})
		writeResp(string(b))
	}

	// Child stderr: capture, scrub through same pipeline, forward to os.Stderr. Never raw.
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		sc := bufio.NewScanner(stderrPipe)
		sc.Buffer(make([]byte, 64*1024), 1024*1024)
		for sc.Scan() {
			line := scrubLine(sc.Text(), vm, allow, scrubMode, sess, thr, emit)
			fmt.Fprintln(os.Stderr, line)
		}
	}()

	// Track last request id for crash error reporting.
	var idMu sync.Mutex
	var lastID any

	// LLM -> server direction with deterministic shutdown via ctx.
	stdinDone := make(chan struct{})
	go func() {
		defer close(stdinDone)
		defer stdin.Close()
		br := bufio.NewReader(os.Stdin)
		fr := &frameReader{br: br, framing: peerFraming, detected: true}
		for {
			select {
			case <-ctx.Done():
				return
			default:
			}
			line, err := fr.read()
			if err != nil {
				return // EOF/broken pipe: close stdin, no deadlock
			}
			if id := extractID(line); id != nil {
				idMu.Lock()
				lastID = id
				idMu.Unlock()
			}
			if findings := checkInbound(line, deny); len(findings) > 0 {
				emit("mcp_blocked", map[string]any{"reason": strings.Join(findings, "; ")})
				writeErrID(extractID(line), strings.Join(findings, "; "))
				continue
			}
			line = sess.Rehydrate(line)
			select {
			case <-ctx.Done():
				return
			default:
			}
			if _, err := io.WriteString(stdin, line+"\n"); err != nil {
				return // broken pipe to child: stop without deadlock
			}
		}
	}()

	// server -> LLM direction.
	childFraming := FramingLine // child assumed line-framed stdio; respond to client in peer framing
	_ = childFraming
	br := bufio.NewReader(stdout)
	cbr := &frameReader{br: br, framing: FramingLine, detected: true}
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			select {
			case <-ctx.Done():
				return
			default:
			}
			line, err := cbr.read()
			if err != nil {
				return
			}
			line = scrubLine(line, vm, allow, scrubMode, sess, thr, emit)
			writeResp(line)
		}
	}()

	waitDone := make(chan error, 1)
	go func() { waitDone <- c.Wait() }()

	select {
	case <-stdinDone:
		// client EOF: let child finish, drain output briefly then exit
		select {
		case err := <-waitDone:
			cancel()
			<-done
			wg.Wait()
			return exitError(err)
		case <-time.After(5 * time.Second):
			cancel()
			<-done
			wg.Wait()
			<-waitDone
			return nil
		}
	case <-done:
		// child stdout EOF: stop reader side, wait child
		cancel()
		<-stdinDone
		wg.Wait()
		err := <-waitDone
		if err != nil {
			idMu.Lock()
			id := lastID
			idMu.Unlock()
			writeErrID(id, "child crashed: "+childErrText(err))
		}
		return exitError(err)
	case err := <-waitDone:
		// child exited (possibly crash/kill mid-request)
		cancel()
		<-done
		<-stdinDone
		wg.Wait()
		if err != nil {
			idMu.Lock()
			id := lastID
			idMu.Unlock()
			writeErrID(id, "child crashed: "+childErrText(err))
		}
		return exitError(err)
	}
}

func childErrText(err error) string {
	if ee, ok := err.(*exec.ExitError); ok {
		return strings.TrimSpace(string(ee.Stderr)) + " " + ee.String()
	}
	return err.Error()
}

// exitError propagates the child's exit code; nil stays nil.
func exitError(err error) error {
	if err == nil {
		return nil
	}
	if ee, ok := err.(*exec.ExitError); ok {
		if ws := ee.ProcessState; ws != nil {
			return &ExitError{Code: ws.ExitCode(), Err: err}
		}
	}
	return err
}

// ExitError carries the child exit code for the caller to propagate.
type ExitError struct {
	Code int
	Err  error
}

func (e *ExitError) Error() string { return e.Err.Error() }
func (e *ExitError) Unwrap() error { return e.Err }

// CodeOf returns the process exit code to propagate (child exit 7 => 7).
func CodeOf(err error) int {
	if err == nil {
		return 0
	}
	var ee *ExitError
	if as := asExitError(err, &ee); as {
		return ee.Code
	}
	if x, ok := err.(*exec.ExitError); ok && x.ProcessState != nil {
		return x.ProcessState.ExitCode()
	}
	return 1
}

func asExitError(err error, target **ExitError) bool {
	for err != nil {
		if ee, ok := err.(*ExitError); ok {
			*target = ee
			return true
		}
		u, ok := err.(interface{ Unwrap() error })
		if !ok {
			return false
		}
		err = u.Unwrap()
	}
	return false
}

func extractID(line string) any {
	var m struct {
		ID any `json:"id"`
	}
	if err := json.Unmarshal([]byte(line), &m); err != nil {
		return nil
	}
	return m.ID
}

// detectPeerFraming peeks stdin once: Content-Length header => CL framing, else line.
func detectPeerFraming() Framing {
	// Non-blocking best effort is hard on os.Stdin; default line unless
	// env override used in tests. Real detection happens per-stream in frameReader.
	if os.Getenv("SENTINEL_MCP_FRAMING") == "content-length" {
		return FramingContentLength
	}
	return FramingLine
}

// frameReader reads one framing (detected once) with caps and named errors.
type frameReader struct {
	br       *bufio.Reader
	framing  Framing
	detected bool
}

func readFrame(br *bufio.Reader) (string, error) {
	fr := &frameReader{br: br}
	return fr.readDetect()
}

func (f *frameReader) read() (string, error) {
	if !f.detected {
		return f.readDetect()
	}
	if f.framing == FramingContentLength {
		return f.readCLBody()
	}
	line, err := readBoundedLine(f.br)
	if err != nil {
		return "", err
	}
	return line, nil
}

// readDetect detects framing once: Content-Length header => CL mode, else line mode.
func (f *frameReader) readDetect() (string, error) {
	line, err := readBoundedLineRaw(f.br)
	if err != nil {
		return "", err
	}
	trimmed := strings.TrimRight(line, "\r\n")
	lower := strings.ToLower(trimmed)
	if strings.HasPrefix(lower, "content-length:") {
		n, herr := parseContentLength(trimmed)
		if herr != nil {
			return "", herr
		}
		f.framing = FramingContentLength
		f.detected = true
		return f.readCLBodyAfterHeader(n)
	}
	if looksLikeMalformedHeader(trimmed) {
		return "", &FrameError{Kind: "malformed_header", Message: "malformed header: " + trimmed}
	}
	f.framing = FramingLine
	f.detected = true
	return strings.TrimRight(line, "\r\n"), nil
}

func (f *frameReader) readCLBody() (string, error) {
	// read header line(s) for each subsequent frame
	line, err := readBoundedLineRaw(f.br)
	if err != nil {
		return "", err
	}
	trimmed := strings.TrimRight(line, "\r\n")
	if !strings.HasPrefix(strings.ToLower(trimmed), "content-length:") {
		if looksLikeMalformedHeader(trimmed) || trimmed != "" {
			return "", &FrameError{Kind: "malformed_header", Message: "expected Content-Length, got: " + trimmed}
		}
		return "", &FrameError{Kind: "malformed_header", Message: "expected Content-Length"}
	}
	n, herr := parseContentLength(trimmed)
	if herr != nil {
		return "", herr
	}
	return f.readCLBodyAfterHeader(n)
}

func parseContentLength(header string) (int, *FrameError) {
	parts := strings.SplitN(header, ":", 2)
	if len(parts) != 2 {
		return 0, &FrameError{Kind: "malformed_header", Message: "bad Content-Length header: " + header}
	}
	v := strings.TrimSpace(parts[1])
	// reject trailing garbage: must be all digits
	if v == "" {
		return 0, &FrameError{Kind: "malformed_header", Message: "empty Content-Length"}
	}
	for _, r := range v {
		if r < '0' || r > '9' {
			return 0, &FrameError{Kind: "malformed_header", Message: "malformed Content-Length: " + header}
		}
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return 0, &FrameError{Kind: "malformed_header", Message: "bad Content-Length: " + header, Err: err}
	}
	if n < 0 {
		return 0, &FrameError{Kind: "malformed_header", Message: "negative Content-Length"}
	}
	if n >= MaxFrameSize {
		return 0, &FrameError{Kind: "too_large", Message: fmt.Sprintf("frame %d exceeds max %d", n, MaxFrameSize)}
	}
	return n, nil
}

func (f *frameReader) readCLBodyAfterHeader(n int) (string, error) {
	// consume blank separator line
	blank, err := readBoundedLineRaw(f.br)
	if err != nil {
		return "", &FrameError{Kind: "truncated", Message: "missing blank line after Content-Length", Err: err}
	}
	if strings.TrimRight(blank, "\r\n") != "" {
		return "", &FrameError{Kind: "malformed_header", Message: "expected blank line after Content-Length"}
	}
	if n == 0 {
		return "", nil
	}
	buf := make([]byte, n)
	_, err = io.ReadFull(f.br, buf)
	if err != nil {
		return "", &FrameError{Kind: "truncated", Message: fmt.Sprintf("truncated body: want %d bytes", n), Err: err}
	}
	return string(buf), nil
}

func readBoundedLineRaw(br *bufio.Reader) (string, error) {
	var sb strings.Builder
	for {
		c, err := br.ReadByte()
		if err != nil {
			if sb.Len() == 0 {
				return "", &FrameError{Kind: "eof", Message: "EOF", Err: io.EOF}
			}
			return "", &FrameError{Kind: "truncated", Message: "EOF mid-line", Err: err}
		}
		sb.WriteByte(c)
		if sb.Len() > MaxFrameSize+1024 {
			return "", &FrameError{Kind: "too_large", Message: "line exceeds max frame size"}
		}
		if c == '\n' {
			return sb.String(), nil
		}
	}
}

func readBoundedLine(br *bufio.Reader) (string, error) {
	s, err := readBoundedLineRaw(br)
	if err != nil {
		return "", err
	}
	return strings.TrimRight(s, "\r\n"), nil
}

func looksLikeMalformedHeader(s string) bool {
	// "word:" with no valid framing but colon-terminated token, or HTTP-like garbage
	if s == "" {
		return false
	}
	if strings.HasPrefix(s, "{") {
		return false
	}
	if strings.Contains(s, ":") && !strings.Contains(s, " ") && !strings.HasPrefix(s, `"`) {
		return true
	}
	return false
}

// checkCall is kept for backwards compatibility; delegates to checkInbound.
func checkCall(line string, deny map[string]bool) string {
	f := checkInbound(line, deny)
	if len(f) == 0 {
		return ""
	}
	return f[0]
}

// checkInbound validates tools/call, resources/read, prompts/get,
// completion/complete. Returns ALL findings, not just the first.
func checkInbound(line string, deny map[string]bool) []string {
	var m struct {
		Method string `json:"method"`
		Params struct {
			Name      string         `json:"name"`
			Arguments map[string]any `json:"arguments"`
			URI       string         `json:"uri"`
			Prompt    *struct {
				Name string `json:"name"`
			} `json:"prompt"`
			Ref  map[string]any `json:"ref"`
			Args map[string]any `json:"argument"`
		} `json:"params"`
	}
	if err := json.Unmarshal([]byte(line), &m); err != nil {
		return nil
	}
	var out []string
	switch m.Method {
	case "tools/call":
		if deny[m.Params.Name] {
			out = append(out, "tool denied: "+m.Params.Name)
		}
		raw, _ := json.Marshal(m.Params.Arguments)
		for _, ph := range placeholder.Find(string(raw)) {
			out = append(out, "foreign placeholder in args: "+ph)
		}
	case "resources/read":
		if m.Params.URI != "" {
			for _, ph := range placeholder.Find(m.Params.URI) {
				out = append(out, "foreign placeholder in uri: "+ph)
			}
			if deny["resource:"+m.Params.URI] {
				out = append(out, "resource denied: "+m.Params.URI)
			}
		}
		raw, _ := json.Marshal(m.Params.Arguments)
		for _, ph := range placeholder.Find(string(raw)) {
			out = append(out, "foreign placeholder in args: "+ph)
		}
	case "prompts/get":
		name := m.Params.Name
		if m.Params.Prompt != nil && m.Params.Prompt.Name != "" {
			name = m.Params.Prompt.Name
		}
		if name != "" && deny["prompt:"+name] {
			out = append(out, "prompt denied: "+name)
		}
		raw, _ := json.Marshal(m.Params.Args)
		if string(raw) != "null" {
			for _, ph := range placeholder.Find(string(raw)) {
				out = append(out, "foreign placeholder in args: "+ph)
			}
		}
	case "completion/complete":
		raw, _ := json.Marshal(m.Params.Ref)
		if string(raw) != "null" {
			for _, ph := range placeholder.Find(string(raw)) {
				out = append(out, "foreign placeholder in ref: "+ph)
			}
		}
	default:
		return nil
	}
	return out
}

func scrubLine(line string, m vault.Matcher, allow map[string]bool, mode string, sess *scrubber.Session, thr float64, emit func(string, map[string]any)) string {
	var mm map[string]any
	if err := json.Unmarshal([]byte(line), &mm); err != nil {
		return line
	}
	if !scrubVal(mm, m, allow, mode, sess, thr, emit) {
		return line
	}
	var buf strings.Builder
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(mm)
	return strings.TrimRight(buf.String(), "\n")
}

// scrubVal walks every string leaf by JSON shape (not a hardcoded key list),
// skipping only SkipFields protocol/schema keys where redaction breaks the protocol.
func scrubVal(v any, m vault.Matcher, allow map[string]bool, mode string, sess *scrubber.Session, thr float64, emit func(string, map[string]any)) bool {
	switch t := v.(type) {
	case map[string]any:
		hit := false
		for k, x := range t {
			if SkipFields[k] {
				continue
			}
			if s, ok := x.(string); ok {
				f := scrubber.ScanWithMatcher(s, m, allow, nil)
				if len(f) == 0 {
					continue
				}
				md := mode
				if hasVaultSecret(f) {
					md = "block_unless_placeholder"
				}
				out, err := scrubber.Apply(s, f, md, sess, thr)
				if err != nil {
					t[k] = "[BLOCKED:" + f[0].Type + "]"
					hit = true
					emit("secret_blocked", map[string]any{"type": f[0].Type})
				} else if out != s {
					t[k] = out
					hit = true
					emit("pii_redacted", map[string]any{"count": len(f)})
				}
			} else if scrubVal(x, m, allow, mode, sess, thr, emit) {
				hit = true
			}
		}
		return hit
	case []any:
		hit := false
		for i, x := range t {
			if s, ok := x.(string); ok {
				f := scrubber.ScanWithMatcher(s, m, allow, nil)
				if len(f) == 0 {
					continue
				}
				md := mode
				if hasVaultSecret(f) {
					md = "block_unless_placeholder"
				}
				out, err := scrubber.Apply(s, f, md, sess, thr)
				if err != nil {
					t[i] = "[BLOCKED:" + f[0].Type + "]"
					hit = true
					emit("secret_blocked", map[string]any{"type": f[0].Type})
				} else if out != s {
					t[i] = out
					hit = true
					emit("pii_redacted", map[string]any{"count": len(f)})
				}
			} else if scrubVal(x, m, allow, mode, sess, thr, emit) {
				hit = true
			}
		}
		return hit
	}
	return false
}

func hasVaultSecret(f []scrubber.Finding) bool {
	for _, x := range f {
		if strings.HasPrefix(x.Type, "SECRET") {
			return true
		}
	}
	return false
}

func writeErr(w *os.File, reason string) {
	b, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": nil, "error": map[string]any{"code": -32602, "message": "sentinel: " + reason}})
	w.Write(append(b, '\n'))
}

func zero(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

var _ = time.Now
