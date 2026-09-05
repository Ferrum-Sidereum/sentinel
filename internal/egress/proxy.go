package egress

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"

	"sentinel/internal/audit"
	"sentinel/internal/ca"
	"sentinel/internal/placeholder"
	"sentinel/internal/vault"
)

type Server struct {
	Addr  string
	Store *vault.Store
	CA    *ca.Authority
	Log   *audit.Logger
	ln    net.Listener
}

func Serve(addr string, st *vault.Store, auth *ca.Authority, log *audit.Logger) (*Server, error) {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, err
	}
	s := &Server{Addr: ln.Addr().String(), Store: st, CA: auth, Log: log, ln: ln}
	go s.accept()
	return s, nil
}
func (s *Server) Stop() error { return s.ln.Close() }
func (s *Server) accept() {
	for {
		c, err := s.ln.Accept()
		if err != nil {
			return
		}
		go s.handle(c)
	}
}
func (s *Server) handle(c net.Conn) {
	defer c.Close()
	br := bufio.NewReader(c)
	peek, err := br.Peek(7)
	if err != nil {
		return
	}
	if strings.HasPrefix(string(peek), "CONNECT") {
		// read full CONNECT line to get target
		line, err := br.ReadString('\n')
		if err != nil {
			return
		}
		parts := strings.SplitN(strings.TrimSpace(line), " ", 3)
		if len(parts) < 2 {
			return
		}
		s.handleConnect(c, br, parts[1])
		return
	}
	req, err := http.ReadRequest(br)
	if err != nil {
		return
	}
	s.serveMITM(c, req, true)
}

func (s *Server) handleConnect(c net.Conn, br *bufio.Reader, target string) {
	host := hostOnly(target)
	if !s.shouldMITM(host) {
		// blind tunnel
		up, err := net.Dial("tcp", target)
		if err != nil {
			return
		}
		defer up.Close()
		c.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))
		relay(c, up, br)
		return
	}
	c.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))
	cert, err := s.CA.CertFor(host)
	if err != nil {
		return
	}
	tc := tls.Server(c, &tls.Config{Certificates: []tls.Certificate{cert}})
	if err := tc.Handshake(); err != nil {
		return
	}
	defer tc.Close()
	tbr := bufio.NewReader(tc)
	for {
		req, err := http.ReadRequest(tbr)
		if err != nil {
			return
		}
		req.URL.Scheme = "https"
		req.URL.Host = target
		s.forward(req, tc, true)
		if req.Close {
			return
		}
	}
}

// plain-HTTP MITM (client sent full URL, no CONNECT)
func (s *Server) serveMITM(c net.Conn, req *http.Request, plain bool) {
	s.forward(req, c, plain)
}

func (s *Server) forward(clientReq *http.Request, w io.Writer, _ bool) {
	host := hostOnly(clientReq.URL.Host)
	if host == "" {
		host = hostOnly(clientReq.Host)
	}
	body, _ := io.ReadAll(clientReq.Body)
	if clientReq.Body != nil {
		clientReq.Body.Close()
	}

	blocked, out := s.substitute(host, clientReq, body)
	bw := bufio.NewWriter(w)
	defer bw.Flush()
	if blocked {
		resp := &http.Response{StatusCode: 403, ProtoMajor: 1, ProtoMinor: 1,
			Header: http.Header{"Content-Type": {"text/plain"}}, Body: io.NopCloser(strings.NewReader("sentinel: secret bind violation"))}
		resp.Write(bw)
		return
	}
	upReq, _ := http.NewRequest(clientReq.Method, clientReq.URL.String(), bytes.NewReader(out))
	upReq.Header = clientReq.Header.Clone()
	upReq.Host = clientReq.Host
	resp, err := http.DefaultTransport.RoundTrip(upReq)
	if err != nil {
		r := &http.Response{StatusCode: 502, ProtoMajor: 1, ProtoMinor: 1,
			Header: http.Header{}, Body: io.NopCloser(strings.NewReader("sentinel: upstream error"))}
		r.Write(bw)
		return
	}
	defer resp.Body.Close()
	rb, _ := io.ReadAll(resp.Body)
	rb = s.scrubEcho(rb)
	resp.Body = io.NopCloser(bytes.NewReader(rb))
	resp.ContentLength = int64(len(rb))
	resp.Write(bw)
}

// substitute placeholders in URL/headers/body. Returns blocked=true on bind violation.
func (s *Server) substitute(host string, req *http.Request, body []byte) (bool, []byte) {
	replace := func(text string, where string) (string, bool) {
		for _, ph := range placeholder.Find(text) {
			name := placeholderName(ph)
			sec, err := s.Store.Get(name)
			if err != nil {
				s.emit("placeholder_invalid", map[string]any{"hint": ph, "host": host})
				return text, true
			}
			if !bound(sec, host, req.URL.Path, req.Method, where) {
				s.emit("secret_blocked", map[string]any{"name": name, "host": host, "reason": "bind"})
				return text, true
			}
			text = strings.ReplaceAll(text, ph, string(sec.Value))
			zero(sec.Value)
			s.emit("secret_injected", map[string]any{"name": name, "host": host, "path": req.URL.Path})
		}
		return text, false
	}
	var blocked bool
	if u := req.URL.String(); placeholder.Find(u) != nil {
		nu, bad := replace(u, "")
		if bad {
			return true, nil
		}
		if r, err := http.NewRequest(req.Method, nu, nil); err == nil {
			req.URL = r.URL
		}
	}
	for k, vv := range req.Header {
		for i, v := range vv {
			if placeholder.Find(v) != nil {
				nv, bad := replace(v, k)
				if bad {
					return true, nil
				}
				req.Header[k][i] = nv
			}
		}
		_ = k
		_ = blocked
	}
	if len(body) > 0 && placeholder.Find(string(body)) != nil {
		nb, bad := replace(string(body), "")
		if bad {
			return true, nil
		}
		body = []byte(nb)
	}
	return false, body
}

// scrubEcho replaces known real secret values in responses with placeholders.
func (s *Server) scrubEcho(body []byte) []byte {
	m, err := s.Store.NewMatcher()
	if err != nil {
		return body
	}
	defer m.Close()
	type span struct {
		s, e int
		name string
	}
	var spans []span
	for _, mt := range m.FindAll(string(body)) {
		spans = append(spans, span{mt.Start, mt.End, mt.Name})
	}
	// replace from end to keep offsets valid
	for i := len(spans) - 1; i >= 0; i-- {
		sp := spans[i]
		nb := append([]byte{}, body[:sp.s]...)
		nb = append(nb, []byte(placeholder.Canonical(sp.name))...)
		nb = append(nb, body[sp.e:]...)
		body = nb
		s.emit("pii_redacted", map[string]any{"type": "SECRET_ECHO", "count": 1})
	}
	return body
}

func (s *Server) shouldMITM(host string) bool {
	names, err := s.Store.List()
	if err != nil {
		return false
	}
	for _, n := range names {
		sec, err := s.Store.Get(n)
		if err != nil {
			continue
		}
		for _, h := range sec.Hosts {
			if strings.EqualFold(h, host) {
				zero(sec.Value)
				return true
			}
		}
		zero(sec.Value)
	}
	return false
}

func (s *Server) tunnelHTTP(c net.Conn, br *bufio.Reader, req *http.Request) {
	up, err := net.Dial("tcp", req.URL.Host)
	if err != nil {
		return
	}
	defer up.Close()
	req.Write(up)
	relay(c, up, br)
}

func relay(a, b net.Conn, bra *bufio.Reader) {
	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); io.Copy(b, bra) }()
	go func() { defer wg.Done(); io.Copy(a, b) }()
	wg.Wait()
}

func (s *Server) emit(typ string, f map[string]any) {
	if s.Log != nil {
		s.Log.Log("", typ, f)
	}
}

func hostOnly(h string) string {
	if i := strings.LastIndex(h, ":"); i >= 0 {
		// careful with IPv6; strip port only if single colon-suffix numeric
		if !strings.Contains(h[i+1:], ":") {
			return h[:i]
		}
	}
	return h
}

func placeholderName(ph string) string {
	if strings.HasPrefix(ph, "snt://") {
		n := strings.TrimPrefix(ph, "snt://")
		if i := strings.Index(n, "@"); i >= 0 {
			n = n[:i]
		}
		return n
	}
	return ph
}

func bound(sec vault.Secret, host, path, method, where string) bool {
	okHost := false
	for _, h := range sec.Hosts {
		if strings.EqualFold(h, host) {
			okHost = true
		}
	}
	if !okHost {
		return false
	}
	if len(sec.Paths) > 0 && !pathMatch(sec.Paths, path) {
		return false
	}
	if len(sec.Methods) > 0 {
		ok := false
		for _, m := range sec.Methods {
			if strings.EqualFold(m, method) {
				ok = true
			}
		}
		if !ok {
			return false
		}
	}
	if len(sec.InjectHdr) > 0 && where != "" {
		ok := false
		for _, h := range sec.InjectHdr {
			if strings.EqualFold(h, where) {
				ok = true
			}
		}
		if !ok {
			return false
		}
	}
	return true
}

func pathMatch(pats []string, path string) bool {
	for _, p := range pats {
		if strings.HasSuffix(p, "*") {
			if strings.HasPrefix(path, strings.TrimSuffix(p, "*")) {
				return true
			}
		} else if p == path {
			return true
		}
	}
	return false
}

func zero(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
