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
	fs := newFlagSet("serve", "usage: sentinel serve [--addr ADDR]")
	var addr string
	fs.StringVar(&addr, "addr", "127.0.0.1:18449", "listen address")
	if err := fs.Parse(args); err != nil {
		return ExitUsage
	}
	if fs.NArg() >= 1 {
		addr = fs.Arg(0)
	}
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
	if l != nil {
		defer l.Close()
	}
	s, err := egress.Serve(addr, st, auth, l)
	if err != nil {
		return failRuntime(err)
	}
	fmt.Println("egress proxy on", s.Addr)
	select {}
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
	proxy := "http://127.0.0.1:18449"
	auth, _ := ca.LoadOrCreate()
	_ = auth
	l, _ := audit.Open(filepath.Join(dataDir(), "audit.jsonl"))
	s, err := egress.Serve("127.0.0.1:18449", st, auth, l)
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

// usage: sentinel llm-serve [listen-addr] [upstream-base]
func cmdLLMServe(args []string) int {
	fs := newFlagSet("llm-serve", "usage: sentinel llm-serve [--addr ADDR] [--upstream URL]")
	var addr, up string
	fs.StringVar(&addr, "addr", "127.0.0.1:18450", "listen address")
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
	polPath := filepath.Join(dataDir(), "policy.yaml")
	p, _ := policy.Load(polPath)
	w := policy.Watch(polPath, &p, 2*time.Second, func(err error) {
		fmt.Fprintln(os.Stderr, "policy reload:", err)
	})
	defer w.Stop()
	gw, err := llm.Serve(addr, up, &p, openAudit())
	if err != nil {
		return failRuntime(err)
	}
	if st, err := openStore(); err == nil {
		gw.Vault = st
		defer st.Close()
	}
	fmt.Println("llm gateway on", gw.Addr, "->", up)
	select {}
}
