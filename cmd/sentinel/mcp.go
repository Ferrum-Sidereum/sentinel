package main

import (
	"fmt"
	"path/filepath"
	"time"

	"sentinel/internal/mcp"
	"sentinel/internal/policy"
	"sentinel/internal/scrubber"
)

func cmdMCP(args []string) int {
	fs := newFlagSet("mcp", "usage: sentinel mcp run [--mode inject|proxy] [--profile NAME] -- <cmd...>\n       sentinel mcp serve [listen-addr] [upstream-url]")
	var mode, profile string
	fs.StringVar(&mode, "mode", mcp.ModeInject, "run mode: inject|proxy")
	fs.StringVar(&profile, "profile", "", "profile name")
	if err := fs.Parse(args); err != nil {
		return ExitUsage
	}
	_ = profile
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
	if mode != mcp.ModeInject && mode != mcp.ModeProxy {
		return failUsage("invalid --mode (inject|proxy)")
	}
	sess := scrubber.NewSession(24 * time.Hour)
	if err := mcp.RunWithMode(rest, mode, st, &p, openAudit(), sess); err != nil {
		return failRuntime(err)
	}
	return ExitOK
}

// usage: sentinel mcp serve [listen-addr] [upstream-url]
func cmdMCPServe(args []string) int {
	addr := "127.0.0.1:18450"
	if len(args) >= 1 {
		addr = args[0]
	}
	upstream := "http://127.0.0.1:3000"
	if len(args) >= 2 {
		upstream = args[1]
	}
	st, err := openStore()
	if err != nil {
		return failRuntime(err)
	}
	defer st.Close()
	polPath := filepath.Join(dataDir(), "policy.yaml")
	p, _ := policy.Load(polPath)
	sess := scrubber.NewSession(24 * time.Hour)
	srv, err := mcp.ServeHTTP(addr, upstream, st, &p, openAudit(), sess)
	if err != nil {
		return failRuntime(err)
	}
	fmt.Println("mcp proxy on", srv.Addr, "->", upstream)
	select {}
}
