package main

import (
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"sentinel/internal/audit"
	"sentinel/internal/runtime"
)

// serveSession holds the cleanup stack for a running gateway.
type serveSession struct {
	dataDir string
	service string
	audit   *audit.Logger
	stop    func()
}

// finish performs clean shutdown: stop listener, flush audit, remove run file.
func (s *serveSession) finish() {
	if s.stop != nil {
		s.stop()
	}
	flushAudit(s.audit)
	_ = runtime.RemoveRunFile(s.dataDir, s.service)
}

// flushAudit logs a shutdown event and closes the logger so the last
// audit.jsonl line is a complete JSON object.
func flushAudit(l *audit.Logger) {
	if l == nil {
		return
	}
	l.Log("cli", "shutdown", map[string]any{"clean": true})
	_ = l.Close()
}

// waitSignal blocks until SIGINT/SIGTERM and returns the signal.
func waitSignal() os.Signal {
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, syscall.SIGINT, syscall.SIGTERM)
	return <-ch
}

// portFlag binds --port (default -1 = unset, flag > env > default) with
// the documented env var. help names both.
func portFlag(fs *flag.FlagSet, p *int, envName string, def int) {
	fs.IntVar(p, "port", -1, fmt.Sprintf("port override (default %d; env %s)", def, envName))
}

// runServeLoop prints the bound address and blocks until SIGINT/SIGTERM,
// then performs clean shutdown and returns ExitOK.
// sigtermTestHook, when non-nil, is invoked instead of blocking (tests).
func runServeLoop(what string, sess *serveSession, sigtermTestHook func()) int {
	fmt.Println(what)
	if sigtermTestHook != nil {
		sigtermTestHook()
	} else {
		sig := waitSignal()
		fmt.Fprintln(os.Stderr, "received", sig, "- shutting down")
	}
	sess.finish()
	return ExitOK
}
