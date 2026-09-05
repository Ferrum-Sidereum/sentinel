package llm

import (
	"bufio"
	"bytes"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"sentinel/internal/audit"
	"sentinel/internal/policy"
	"sentinel/internal/scrubber"
)

// Gateway: reverse-proxy OpenAI-совместимого /v1 с pseudonymize входящих и rehydrate ответов.
type Gateway struct {
	Addr     string
	Upstream string // e.g. http://127.0.0.1:PORT
	Pol      *policy.Policy
	Log      *audit.Logger
	Sess     *scrubber.Session
	Vault    VaultSnapshotter
	ln       net.Listener
}

// VaultSnapshotter supplies name->plaintext for L0 vault-match. Always on.
type VaultSnapshotter interface {
	ValuesSnapshot() map[string]string
}

func Serve(addr, upstream string, p *policy.Policy, l *audit.Logger) (*Gateway, error) {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, err
	}
	g := &Gateway{Addr: ln.Addr().String(), Upstream: strings.TrimRight(upstream, "/"), Pol: p, Log: l,
		Sess: scrubber.NewSession(24 * time.Hour)}
	go http.Serve(ln, g)
	g.ln = ln
	return g, nil
}

func (g *Gateway) Stop() error { return g.ln.Close() }

func (g *Gateway) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == "/metrics" && r.Method == "GET" {
		Metrics.Handler().ServeHTTP(w, r)
		return
	}
	if r.URL.Path == "/ui" && r.Method == "GET" {
		UIHandler().ServeHTTP(w, r)
		return
	}
	if r.Method != "POST" || !strings.HasPrefix(r.URL.Path, "/v1/") {
		http.Error(w, "sentinel llm gateway: only POST /v1/*", 404)
		return
	}
	if strings.HasPrefix(r.URL.Path, "/v1/embeddings") || strings.HasPrefix(r.URL.Path, "/v1/images") || strings.HasPrefix(r.URL.Path, "/v1/audio") {
		http.Error(w, "sentinel: embeddings/vision/audio blocked by policy", 403)
		g.emit("llm_blocked", 1)
		return
	}
	body, _ := io.ReadAll(r.Body)
	var msg struct {
		Model  string `json:"model"`
		Stream bool   `json:"stream"`
	}
	if err := json.Unmarshal(body, &msg); err != nil {
		http.Error(w, "bad json", 400)
		return
	}
	thr := g.Pol.Defaults.ConfidenceThreshold
	if thr == 0 {
		thr = 0.7
	}
	allow := map[string]bool{}
	for _, v := range g.Pol.Allowlist.Values {
		allow[v] = true
	}
	// scrub each message content with pseudonymize
	var raw struct {
		Model    string `json:"model"`
		Messages []struct {
			Role    string `json:"role"`
			Content string `json:"content"`
		} `json:"messages"`
	}
	json.Unmarshal(body, &raw)
	blocked := false
	for i, m := range raw.Messages {
		start := time.Now()
		var vv map[string]string
		if g.Vault != nil {
			vv = g.Vault.ValuesSnapshot()
		}
		f := scrubber.Scan(m.Content, vv, allow)
		for _, x := range f {
			Metrics.AddFinding(x.Type, 1)
		}
		Metrics.ObserveLatency(time.Since(start))
		// L0: real vault values never go to LLM — always block unless placeholder.
		mode := ""
		if hasSecret(f) {
			mode = "block_unless_placeholder"
		} else {
			mode = g.Pol.ModeFor(shortEnt(f), "llm")
		}
		if mode == "" {
			mode = g.Pol.Defaults.ScrubToLLM
		}
		if mode == "" {
			mode = "pseudonymize"
		}
		out, err := scrubber.Apply(m.Content, f, mode, g.Sess, thr)
		if err != nil {
			blocked = true
			break
		}
		raw.Messages[i].Content = out
		g.emit("pii_redacted", len(f))
		recordEvent("pii_redacted")
	}
	if blocked {
		http.Error(w, "sentinel: blocked by policy", 403)
		return
	}
	fwd, _ := json.Marshal(raw)
	upReq, _ := http.NewRequest("POST", g.Upstream+r.URL.Path, bytes.NewReader(fwd))
	upReq.Header.Set("Content-Type", "application/json")
	for k, v := range r.Header {
		if strings.HasPrefix(strings.ToLower(k), "x-sentinel") || strings.ToLower(k) == "authorization" {
			upReq.Header[k] = v
		}
	}
	resp, err := http.DefaultClient.Do(upReq)
	if err != nil {
		http.Error(w, "upstream error", 502)
		return
	}
	defer resp.Body.Close()
	if msg.Stream || strings.Contains(resp.Header.Get("Content-Type"), "text/event-stream") {
		g.streamRehydrate(w, resp)
		return
	}
	rb, _ := io.ReadAll(resp.Body)
	// rehydrate aliases in response text (incl. JSON-escaped \u003c...\u003e form)
	text := g.Sess.Rehydrate(unescapeAngle(string(rb)))
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(resp.StatusCode)
	w.Write([]byte(text))
}

// streamRehydrate proxies SSE chunks, rehydrating aliases with a window buffer
// (§6.5): a pseudonym like <EMAIL_1> may arrive split across TCP chunks or
// across consecutive data: lines, so per-line Rehydrate would miss it.
// Payloads accumulate in pending; only the safe prefix (up to a possible
// partial "<..." tail) is rehydrated and forwarded, the tail is held back.
// The remainder flushes on sentence boundary, size threshold, [DONE] or EOF.
func (g *Gateway) streamRehydrate(w http.ResponseWriter, resp *http.Response) {
	w.Header().Set("Content-Type", "text/event-stream")
	w.WriteHeader(resp.StatusCode)
	fl, _ := w.(http.Flusher)
	const maxBuf = 256
	var pending string
	flush := func(force bool) {
		if pending == "" {
			return
		}
		safe := len(pending)
		if !force {
			if i := strings.LastIndex(pending, "<"); i >= 0 && !strings.Contains(pending[i:], ">") {
				if len(pending) < 4096 {
					return // partial alias: keep accumulating, emit nothing yet
				}
				safe = i // oversized: emit head, hold tail
			} else if len(pending) < maxBuf && !endsSentence(pending) {
				return // keep accumulating the window
			}
		}
		if safe == 0 {
			return
		}
		head, tail := pending[:safe], pending[safe:]
		w.Write([]byte("data:" + g.Sess.Rehydrate(head) + "\n"))
		if fl != nil {
			fl.Flush()
		}
		pending = tail
	}
	br := bufio.NewReader(resp.Body)
	for {
		line, err := br.ReadString('\n')
		if line != "" {
			if strings.TrimSpace(line) == "" {
				continue // SSE event separator: keep window, emit on flush
			}
			if strings.HasPrefix(line, "data:") {
				payload := unescapeAngle(strings.TrimPrefix(line, "data:"))
				payload = strings.TrimPrefix(payload, " ")
				payload = strings.TrimSuffix(payload, "\n")
				if strings.TrimSpace(payload) == "[DONE]" {
					flush(true)
					w.Write([]byte(line))
					if fl != nil {
						fl.Flush()
					}
				} else {
					pending += payload
					flush(false)
				}
			} else {
				flush(true)
				w.Write([]byte(line))
				if fl != nil {
					fl.Flush()
				}
			}
		}
		if err != nil {
			break
		}
	}
	flush(true)
}

func endsSentence(s string) bool {
	s = strings.TrimRight(s, " \t")
	if s == "" {
		return false
	}
	switch s[len(s)-1] {
	case '.', '!', '?', '\n', ':', ';':
		return true
	}
	return false
}

func unescapeAngle(s string) string {
	return strings.ReplaceAll(strings.ReplaceAll(s, `\u003c`, "<"), `\u003e`, ">")
}

func shortEnt(f []scrubber.Finding) string {
	if len(f) == 0 {
		return ""
	}
	t := f[0].Type
	if i := strings.Index(t, ":"); i >= 0 {
		return "SECRET"
	}
	return t
}

func hasSecret(f []scrubber.Finding) bool {
	for _, x := range f {
		if strings.HasPrefix(x.Type, "SECRET") {
			return true
		}
	}
	return false
}

func (g *Gateway) emit(typ string, n int) {
	if g.Log == nil {
		return
	}
	g.Log.Log("", "pii_redacted", map[string]any{"count": n})
}
