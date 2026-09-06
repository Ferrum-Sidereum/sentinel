package main

import (
	"context"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"sentinel/internal/mcp"
	"sentinel/internal/policy"
	"sentinel/internal/runtime"
	"sentinel/internal/scrubber"
)

func cmdMCP(args []string) int {
	fs := newFlagSet("mcp", "usage: sentinel mcp run [--mode broker|inject|proxy] [--dest HOST]... [--allow-unbound] [--profile NAME] [--strict] [--yes-i-know] -- <cmd...>\n       sentinel mcp serve [listen-addr] [upstream-url]")
	var mode, profile string
	var strict, yesIKnow, allowUnbound bool
	var dests multiFlag
	fs.StringVar(&mode, "mode", mcp.ModeBroker, "run mode: broker|inject|proxy (broker default, inject explicit)")
	fs.StringVar(&profile, "profile", "", "profile name")
	fs.Var(&dests, "dest", "declared destination host (repeatable)")
	fs.BoolVar(&allowUnbound, "allow-unbound", false, "allow wildcard/unbound injection (warns)")
	fs.BoolVar(&strict, "strict", false, "denied approvals exit 4 instead of leaving snt:// placeholder")
	fs.BoolVar(&yesIKnow, "yes-i-know", false, "auto-allow all approvals (demos/tests only, never default)")
	if err := fs.Parse(args); err != nil {
		return ExitUsage
	}
	rest := fs.Args()
	if len(rest) < 1 || (rest[0] != "run" && rest[0] != "serve") {
		return failUsage("sentinel mcp run ... | sentinel mcp serve ...")
	}
	if rest[0] == "serve" {
		return cmdMCPServe(rest[1:])
	}
	st, err := openStore()
	if err != nil {
		return failRuntime(err)
	}
	defer st.Close()
	polPath := filepath.Join(dataDir(), "policy.yaml")
	p, _ := policy.Load(polPath)
	if mode != mcp.ModeInject && mode != mcp.ModeProxy && mode != mcp.ModeBroker {
		return failUsage("invalid --mode (broker|inject|proxy)")
	}
	mcp.Strict = strict
	if yesIKnow {
		p.Approvals.Default = "allow"
		p.Approvals.Rules = nil
	}
	sess := scrubber.NewSession(24 * time.Hour)
	if err := mcp.RunWithOptions(rest, mode, mcp.RunOptions{Dests: dests, AllowUnbound: allowUnbound}, st, &p, openAudit(), sess); err != nil {
		return failRuntime(err)
	}
	return ExitOK
}

// usage: sentinel mcp serve [--port N] [listen-addr] [upstream-url]
func cmdMCPServe(args []string) int {
	addr := "127.0.0.1:18450"
	upstream := "http://127.0.0.1:3000"
	var port int = -1
	rest := args
	// Pre-scan --port/--port=N before positional args.
	var positional []string
	for i := 0; i < len(rest); i++ {
		a := rest[i]
		if a == "--port" && i+1 < len(rest) {
			if n, err := strconv.Atoi(rest[i+1]); err == nil {
				port = n
			}
			i++
			continue
		}
		if strings.HasPrefix(a, "--port=") {
			if n, err := strconv.Atoi(strings.TrimPrefix(a, "--port=")); err == nil {
				port = n
			}
			continue
		}
		positional = append(positional, a)
	}
	if len(positional) >= 1 {
		addr = positional[0]
	}
	if len(positional) >= 2 {
		upstream = positional[1]
	}
	port = runtime.ResolvePort(port, runtime.EnvMCPPort, runtime.DefaultMCPPort)
	addr = runtime.ResolveAddr(addr, "127.0.0.1", port, runtime.DefaultMCPPort)
	// Pre-bind to surface errors with a helpful hint and to resolve :0.
	ln, err := runtime.Listen(addr)
	if err != nil {
		return failRuntime(err)
	}
	_ = ln.Close()
	st, err := openStore()
	if err != nil {
		return failRuntime(err)
	}
	defer st.Close()
	polPath := filepath.Join(dataDir(), "policy.yaml")
	p, _ := policy.Load(polPath)
	sess := scrubber.NewSession(24 * time.Hour)
	l := openAudit()
	if l != nil {
		defer l.Close()
	}
	srv, err := mcp.ServeHTTP(addr, upstream, st, &p, l, sess)
	if err != nil {
		flushAudit(l)
		return failRuntime(runtime.WrapBind(addr, err))
	}
	_ = runtime.WriteRunFile(dataDir(), runtime.ServiceMCP, addr, version)
	sess2 := &serveSession{dataDir: dataDir(), service: runtime.ServiceMCP, audit: l, stop: func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(ctx)
	}}
	return runServeLoop("mcp proxy on "+addr+" -> "+upstream, sess2, nil)
}
