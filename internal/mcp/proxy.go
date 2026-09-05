package mcp

import (
	"bufio"
	"bytes"
	"io"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"

	"sentinel/internal/audit"
	"sentinel/internal/placeholder"
	"sentinel/internal/policy"
	"sentinel/internal/scrubber"
	"sentinel/internal/vault"
)

// ServeHTTP reverse-proxies to a remote MCP HTTP/SSE server at upstream.
// It substitutes snt:// placeholders in Authorization per secret bind hosts,
// and scrubs JSON/SSE result bodies before returning them to the client.
func ServeHTTP(addr, upstream string, st *vault.Store, p *policy.Policy, l *audit.Logger, sess *scrubber.Session) (*http.Server, error) {
	target, err := url.Parse(upstream)
	if err != nil {
		return nil, err
	}
	scrubMode := p.Defaults.ScrubToLLM
	if scrubMode == "" {
		scrubMode = "pseudonymize"
	}
	thr := p.Defaults.ConfidenceThreshold
	if thr == 0 {
		thr = 0.7
	}
	allow := map[string]bool{}
	for _, v := range p.Allowlist.Values {
		allow[v] = true
	}
	emit := func(typ string, f map[string]any) {
		if l != nil {
			l.Log("", typ, f)
		}
	}
	px := &httputil.ReverseProxy{
		Rewrite: func(r *httputil.ProxyRequest) {
			r.SetURL(target)
			r.Out.Host = target.Host
			// Substitute Authorization placeholders only if secret binds this host.
			auth := r.Out.Header.Get("Authorization")
			for _, ph := range placeholder.Find(auth) {
				sec, err := st.Get(strings.TrimPrefix(ph, "snt://"))
				if err != nil {
					continue
				}
				ok := len(sec.Hosts) == 0
				for _, h := range sec.Hosts {
					if h == target.Hostname() {
						ok = true
						break
					}
				}
				if ok {
					auth = strings.ReplaceAll(auth, ph, string(sec.Value))
				}
				zero(sec.Value)
			}
			r.Out.Header.Set("Authorization", auth)
		},
		ModifyResponse: func(resp *http.Response) error {
			ct := resp.Header.Get("Content-Type")
			if !strings.Contains(ct, "json") && !strings.Contains(ct, "event-stream") && !strings.Contains(ct, "text") {
				return nil
			}
			body, err := io.ReadAll(resp.Body)
			if err != nil {
				return err
			}
			resp.Body.Close()
			var vv map[string]string
			if st != nil {
				vv = st.ValuesSnapshot()
			}
			out := scrubBody(string(body), vv, allow, scrubMode, sess, thr, emit)
			resp.Body = io.NopCloser(strings.NewReader(out))
			resp.ContentLength = int64(len(out))
			resp.Header.Del("Content-Length")
			return nil
		},
	}
	srv := &http.Server{Addr: addr, Handler: px}
	go func() { _ = srv.ListenAndServe() }()
	return srv, nil
}

func scrubBody(body string, vaultVals map[string]string, allow map[string]bool, mode string, sess *scrubber.Session, thr float64, emit func(string, map[string]any)) string {
	var buf bytes.Buffer
	sc := bufio.NewScanner(strings.NewReader(body))
	sc.Buffer(make([]byte, 1024*1024), 1024*1024)
	for sc.Scan() {
		line := sc.Text()
		payload := strings.TrimPrefix(line, "data: ")
		scrubbed := scrubLine(payload, vaultVals, allow, mode, sess, thr, emit)
		if scrubbed != payload {
			line = strings.Replace(line, payload, scrubbed, 1)
		}
		buf.WriteString(line + "\n")
	}
	if buf.Len() == 0 {
		return scrubLine(body, vaultVals, allow, mode, sess, thr, emit)
	}
	return buf.String()
}
