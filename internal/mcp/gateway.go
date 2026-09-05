package mcp

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
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
	_ = mode // stdio secret mode (inject|proxy); scrub mode is scrubMode below
	allow := map[string]bool{}
	for _, v := range p.Allowlist.Values {
		allow[v] = true
	}
	deny := map[string]bool{}
	_ = profile
	if profile != "" {
		// per-profile deny_tools from policy entities? keep simple: profile.DenyTools via Entities key "mcp:deny:<tool>"
		for k := range p.Entities {
			if strings.HasPrefix(k, "mcp:deny:") {
				deny[strings.TrimPrefix(k, "mcp:deny:")] = true
			}
		}
	}

	// inject mode: resolve placeholders in env for child only.
	// proxy mode: leave placeholders; child traffic goes via egress proxy.
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

	c := exec.Command(args[i], args[i+1:]...)
	c.Env = env
	stdin, _ := c.StdinPipe()
	stdout, _ := c.StdoutPipe()
	c.Stderr = os.Stderr
	if err := c.Start(); err != nil {
		return err
	}
	emit := func(typ string, f map[string]any) {
		if l != nil {
			l.Log("", typ, f)
		}
	}

	// LLM -> server direction
	go func() {
		br := bufio.NewReader(os.Stdin)
		for {
			line, err := readFrame(br)
			if err != nil {
				stdin.Close()
				return
			}
			if bad := checkCall(line, deny); bad != "" {
				emit("mcp_blocked", map[string]any{"reason": bad})
				writeErr(os.Stdout, bad)
				continue
			}
			// de-tokenize aliases in args
			line = sess.Rehydrate(line)
			stdin.Write([]byte(line + "\n"))
		}
	}()
	// server -> LLM direction: scrub text fields; L0 vault-match always on
	var vm vault.Matcher
	if st != nil {
		if m, err := st.NewMatcher(); err == nil {
			vm = m
			defer m.Close()
		}
	}
	br := bufio.NewReader(stdout)
	for {
		line, err := readFrame(br)
		if err != nil {
			break
		}
		line = scrubLine(line, vm, allow, scrubMode, sess, thr, emit)
		os.Stdout.Write([]byte(line + "\n"))
	}
	c.Wait()
	return nil
}

func readFrame(br *bufio.Reader) (string, error) {
	line, err := br.ReadString('\n')
	if err != nil && len(line) == 0 {
		return "", err
	}
	// support Content-Length framing
	if strings.HasPrefix(strings.ToLower(line), "content-length:") {
		var n int
		fmt.Sscanf(line, "Content-Length: %d", &n)
		br.ReadString('\n') // blank
		buf := make([]byte, n)
		io.ReadFull(br, buf)
		return string(buf), nil
	}
	return strings.TrimRight(line, "\r\n"), nil
}

func checkCall(line string, deny map[string]bool) string {
	var m struct {
		Method string `json:"method"`
		Params struct {
			Name      string         `json:"name"`
			Arguments map[string]any `json:"arguments"`
		} `json:"params"`
	}
	if err := json.Unmarshal([]byte(line), &m); err != nil {
		return ""
	}
	if m.Method != "tools/call" {
		return ""
	}
	if deny[m.Params.Name] {
		return "tool denied: " + m.Params.Name
	}
	raw, _ := json.Marshal(m.Params.Arguments)
	for _, ph := range placeholder.Find(string(raw)) {
		return "foreign placeholder in args: " + ph
	}
	return ""
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

func scrubVal(v any, m vault.Matcher, allow map[string]bool, mode string, sess *scrubber.Session, thr float64, emit func(string, map[string]any)) bool {
	switch t := v.(type) {
	case map[string]any:
		hit := false
		for k, x := range t {
			if s, ok := x.(string); ok && (k == "text" || k == "content" || k == "description") {
				f := scrubber.ScanWithMatcher(s, m, allow, nil)
				if len(f) == 0 {
					continue
				}
				m := mode
				if hasVaultSecret(f) {
					m = "block_unless_placeholder"
				}
				out, err := scrubber.Apply(s, f, m, sess, thr)
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
		for _, x := range t {
			if scrubVal(x, m, allow, mode, sess, thr, emit) {
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
