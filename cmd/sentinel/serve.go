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

func cmdTrustCA() {
	a, err := ca.LoadOrCreate()
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	_ = a
	caPath := filepath.Join(dataDir(), "ca.pem")
	fmt.Println("CA cert:", caPath)
	cmd := exec.Command("certutil", "-addstore", "-user", "Root", caPath)
	out, err := cmd.CombinedOutput()
	fmt.Println(string(out))
	if err != nil {
		fmt.Println("auto-install failed, install manually:", err)
		os.Exit(1)
	}
	fmt.Println("installed to user Root store")
}

func cmdServe(args []string) {
	addr := "127.0.0.1:18449"
	if len(args) >= 1 {
		addr = args[0]
	}
	st, err := openStore()
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	defer st.Close()
	auth, err := ca.LoadOrCreate()
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	l := openAudit()
	if l != nil {
		defer l.Close()
	}
	s, err := egress.Serve(addr, st, auth, l)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	fmt.Println("egress proxy on", s.Addr)
	select {}
}

func cmdRun(args []string) {
	i := 0
	for i < len(args) && args[i] != "--" {
		i++
	}
	if i < len(args) && args[i] == "--" {
		i++
	}
	if i >= len(args) {
		fmt.Println("usage: sentinel run -- <cmd...>")
		os.Exit(2)
	}
	st, err := openStore()
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	defer st.Close()
	// env with placeholders
	names, _ := st.List()
	env := os.Environ()
	_ = names
	proxy := "http://127.0.0.1:18449"
	auth, _ := ca.LoadOrCreate()
	_ = auth
	l, _ := audit.Open(filepath.Join(dataDir(), "audit.jsonl"))
	s, err := egress.Serve("127.0.0.1:18449", st, auth, l)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	defer s.Stop()
	env = append(env, "HTTP_PROXY="+proxy, "HTTPS_PROXY="+proxy,
		"http_proxy="+proxy, "https_proxy="+proxy,
		"SSL_CERT_FILE="+filepath.Join(dataDir(), "ca.pem"))
	c := exec.Command(args[i], args[i+1:]...)
	c.Env = env
	c.Stdin, c.Stdout, c.Stderr = os.Stdin, os.Stdout, os.Stderr
	if err := c.Run(); err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			os.Exit(ee.ExitCode())
		}
		fmt.Println(err)
		os.Exit(1)
	}
}

// usage: sentinel llm-serve [listen-addr] [upstream-base]
func cmdLLMServe(args []string) {
	addr, up := "127.0.0.1:18450", "https://api.openai.com"
	if len(args) >= 1 {
		addr = args[0]
	}
	if len(args) >= 2 {
		up = args[1]
	}
	polPath := filepath.Join(dataDir(), "policy.yaml")
	p, _ := policy.Load(polPath)
	w := policy.Watch(polPath, &p, 2*time.Second, func(err error) {
		fmt.Fprintln(os.Stderr, "policy reload:", err)
	})
	defer w.Stop()
	g, err := llm.Serve(addr, up, &p, openAudit())
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	if st, err := openStore(); err == nil {
		g.Vault = st
		defer st.Close()
	}
	fmt.Println("llm gateway on", g.Addr, "->", up)
	select {}
}
