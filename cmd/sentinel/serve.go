package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sentinel/internal/audit"
	"sentinel/internal/ca"
	"sentinel/internal/egress"
	"sentinel/internal/llm"
	"sentinel/internal/policy"
	"sentinel/internal/runtime"
	"time"
)

func cmdTrustCA(args []string) int {
	fs := newFlagSet("trust-ca", "usage: sentinel trust-ca")
	if err := fs.Parse(args); err != nil {
		return ExitUsage
	}
	a, err := ca.LoadOrCreate()
	if err != nil {
		return failRuntime(err)
	}
	_ = a
	caPath := filepath.Join(dataDir(), "ca.pem")
	fmt.Println("CA cert:", caPath)
	cmd := exec.Command("certutil", "-addstore", "-user", "Root", caPath)
	out, err := cmd.CombinedOutput()
	fmt.Println(string(out))
	if err != nil {
		fmt.Fprintln(os.Stderr, "auto-install failed, install manually:", err)
		return ExitRuntime
	}
	fmt.Println("installed to user Root store")
	return ExitOK
}

func cmdServe(args []string) int {
	fs := newFlagSet("serve", "usage: sentinel serve [--addr ADDR] [--port N]  (default 127.0.0.1:18449; env SENTINEL_EGRESS_PORT)")
	var addr string
	var port int
	fs.StringVar(&addr, "addr", "127.0.0.1:18449", "listen address")
	portFlag(fs, &port, runtime.EnvEgressPort, runtime.DefaultEgressPort)
	if err := fs.Parse(args); err != nil {
		return ExitUsage
	}
	if fs.NArg() >= 1 {
		addr = fs.Arg(0)
	}
	port = runtime.ResolvePort(port, runtime.EnvEgressPort, runtime.DefaultEgressPort)
	addr = runtime.ResolveAddr(addr, "127.0.0.1", port, runtime.DefaultEgressPort)
	st, err := openStore()
	if err != nil {
		return failRuntime(err)
	}
	defer st.Close()
	auth, err := ca.LoadOrCreate()
	if err != nil {
		return failRuntime(err)
	}
	l := openAudit()
	s, err := egress.Serve(addr, st, auth, l)
	if err != nil {
		flushAudit(l)
		return failRuntime(runtime.WrapBind(addr, err))
	}
	_ = runtime.WriteRunFile(dataDir(), runtime.ServiceEgress, s.Addr, version)
	sess := &serveSession{dataDir: dataDir(), service: runtime.ServiceEgress, audit: l, stop: func() { _ = s.Stop() }}
	return runServeLoop("egress proxy on "+s.Addr, sess, nil)
}

func cmdRun(args []string) int {
	fs := newFlagSet("run", "usage: sentinel run -- <cmd...>")
	if err := fs.Parse(args); err != nil {
		return ExitUsage
	}
	rest := fs.Args()
	if len(rest) == 0 {
		return failUsage("sentinel run -- <cmd...>")
	}
	st, err := openStore()
	if err != nil {
		return failRuntime(err)
	}
	defer st.Close()
	names, _ := st.List()
	env := os.Environ()
	_ = names
	egressPort := runtime.ResolvePort(-1, runtime.EnvEgressPort, runtime.DefaultEgressPort)
	egressAddr := runtime.ResolveAddr("127.0.0.1:18449", "127.0.0.1", egressPort, runtime.DefaultEgressPort)
	proxy := "http://" + egressAddr
	auth, _ := ca.LoadOrCreate()
	_ = auth
	l, _ := audit.Open(filepath.Join(dataDir(), "audit.jsonl"))
	s, err := egress.Serve(egressAddr, st, auth, l)
	if err != nil {
		return failRuntime(err)
	}
	defer s.Stop()
	env = append(env, "HTTP_PROXY="+proxy, "HTTPS_PROXY="+proxy,
		"http_proxy="+proxy, "https_proxy="+proxy,
		"SSL_CERT_FILE="+filepath.Join(dataDir(), "ca.pem"))
	c := exec.Command(rest[0], rest[1:]...)
	c.Env = env
	c.Stdin, c.Stdout, c.Stderr = os.Stdin, os.Stdout, os.Stderr
	if err := c.Run(); err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			os.Exit(ee.ExitCode())
		}
		return failRuntime(err)
	}
	return ExitOK
}

// usage: sentinel llm-serve [listen-addr] [upstream-base] [--port N]
func cmdLLMServe(args []string) int {
	fs := newFlagSet("llm-serve", "usage: sentinel llm-serve [--addr ADDR] [--port N] [--upstream URL]  (default 127.0.0.1:18451; env SENTINEL_LLM_PORT)")
	var addr, up string
	var port int
	fs.StringVar(&addr, "addr", "127.0.0.1:18451", "listen address")
	portFlag(fs, &port, runtime.EnvLLMPort, runtime.DefaultLLMPort)
	fs.StringVar(&up, "upstream", "https://api.openai.com", "upstream base URL")
	if err := fs.Parse(args); err != nil {
		return ExitUsage
	}
	if fs.NArg() >= 1 {
		addr = fs.Arg(0)
	}
	if fs.NArg() >= 2 {
		up = fs.Arg(1)
	}
	port = runtime.ResolvePort(port, runtime.EnvLLMPort, runtime.DefaultLLMPort)
	polPath := filepath.Join(dataDir(), "policy.yaml")
	p, _ := policy.Load(polPath)
	w := policy.Watch(polPath, &p, 2*time.Second, func(err error) {
		fmt.Fprintln(os.Stderr, "policy reload:", err)
	})
	defer w.Stop()
	gw, err := llm.Serve(addr, up, &p, openAudit())
	if err != nil {
		return failRuntime(runtime.WrapBind(addr, err))
	}
	if st, err := openStore(); err == nil {
		gw.Vault = st
		defer st.Close()
	}
	l := openAudit()
	if l != nil {
		defer l.Close()
	}
	_ = runtime.WriteRunFile(dataDir(), runtime.ServiceLLM, gw.Addr, version)
	sess := &serveSession{dataDir: dataDir(), service: runtime.ServiceLLM, audit: l, stop: func() { _ = gw.Stop() }}
	return runServeLoop("llm gateway on "+gw.Addr+" -> "+up, sess, nil)
}
