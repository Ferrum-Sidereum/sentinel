package main

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

	"sentinel/internal/mcp"
	"sentinel/internal/policy"
	"sentinel/internal/scrubber"
)

func cmdMCP(args []string) {
	if len(args) < 1 || (args[0] != "run" && args[0] != "serve") {
		fmt.Println("usage: sentinel mcp run [--mode inject|proxy] [--profile NAME] -- <cmd...>")
		fmt.Println("       sentinel mcp serve [listen-addr] [upstream-url]")
		os.Exit(2)
	}
	if args[0] == "serve" {
		cmdMCPServe(args[1:])
		return
	}
	st, err := openStore()
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	defer st.Close()
	polPath := filepath.Join(dataDir(), "policy.yaml")
	p, _ := policy.Load(polPath)
	mode := mcp.ModeInject
	for k, a := range args {
		if a == "--mode" && k+1 < len(args) && (args[k+1] == mcp.ModeInject || args[k+1] == mcp.ModeProxy) {
			mode = args[k+1]
		}
	}
	sess := scrubber.NewSession(24 * time.Hour)
	if err := mcp.RunWithMode(args[1:], mode, st, &p, openAudit(), sess); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

// usage: sentinel mcp serve [listen-addr] [upstream-url]
func cmdMCPServe(args []string) {
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
		fmt.Println(err)
		os.Exit(1)
	}
	defer st.Close()
	polPath := filepath.Join(dataDir(), "policy.yaml")
	p, _ := policy.Load(polPath)
	sess := scrubber.NewSession(24 * time.Hour)
	srv, err := mcp.ServeHTTP(addr, upstream, st, &p, openAudit(), sess)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	fmt.Println("mcp proxy on", srv.Addr, "->", upstream)
	select {}
}
