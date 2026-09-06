package runtime

import (
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDefaultsDistinct(t *testing.T) {
	seen := map[int]string{}
	for _, d := range []struct {
		port int
		name string
	}{
		{DefaultEgressPort, ServiceEgress},
		{DefaultMCPPort, ServiceMCP},
		{DefaultLLMPort, ServiceLLM},
	} {
		if prev, ok := seen[d.port]; ok {
			t.Fatalf("port %d shared by %s and %s", d.port, prev, d.name)
		}
		seen[d.port] = d.name
	}
	if DefaultEgressPort != 18449 || DefaultMCPPort != 18450 || DefaultLLMPort != 18451 {
		t.Fatal("default ports changed from spec")
	}
}

func TestResolvePortPrecedence(t *testing.T) {
	t.Setenv(EnvMCPPort, "19999")
	if got := ResolvePort(18888, EnvMCPPort, DefaultMCPPort); got != 18888 {
		t.Fatalf("flag should win, got %d", got)
	}
	if got := ResolvePort(-1, EnvMCPPort, DefaultMCPPort); got != 19999 {
		t.Fatalf("env should win, got %d", got)
	}
	t.Setenv(EnvMCPPort, "bogus")
	if got := ResolvePort(-1, EnvMCPPort, DefaultMCPPort); got != DefaultMCPPort {
		t.Fatalf("bad env should fall back, got %d", got)
	}
}

func TestPortZeroBindsFreePort(t *testing.T) {
	ln, err := Listen("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	addr := ln.Addr().String()
	if AddrPort(addr) == 0 {
		t.Fatal("expected resolved free port")
	}
	if err := DialConnect(addr); err != nil {
		t.Fatalf("free port not connectable: %v", err)
	}
}

func TestBindErrorHint(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	addr := ln.Addr().String()
	if _, err := Listen(addr); err == nil {
		t.Fatal("expected bind failure")
	} else {
		msg := err.Error()
		if !strings.Contains(msg, "--port") {
			t.Fatalf("hint missing --port: %q", msg)
		}
	}
	// Default-port collision names the expected service.
	dummy := &BindError{Addr: "127.0.0.1:18450", Port: 18450, Expected: ExpectedService(18450), Err: err}
	if !strings.Contains(dummy.Error(), ServiceMCP) {
		t.Fatalf("expected mcp hint: %q", dummy.Error())
	}
}

func TestRunFileRoundTripAndStale(t *testing.T) {
	dir := t.TempDir()
	if err := WriteRunFile(dir, ServiceMCP, "127.0.0.1:18450", "dev"); err != nil {
		t.Fatal(err)
	}
	rf, err := ReadRunFile(dir, ServiceMCP)
	if err != nil {
		t.Fatal(err)
	}
	if rf.PID != os.Getpid() || rf.Service != ServiceMCP || rf.Addr == "" || rf.StartedAt == "" {
		t.Fatalf("bad run file: %+v", rf)
	}
	buf, _ := os.ReadFile(filepath.Join(dir, "run", "mcp.json"))
	var raw map[string]any
	if err := json.Unmarshal(buf, &raw); err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"pid", "addr", "service", "started_at", "version"} {
		if _, ok := raw[k]; !ok {
			t.Fatalf("run file missing %s", k)
		}
	}
	// Stale file with dead pid is cleaned.
	dead := RunFile{PID: 1 << 30, Addr: "x", Service: ServiceEgress, StartedAt: "t", Version: "v"}
	b, _ := json.Marshal(dead)
	os.MkdirAll(filepath.Join(dir, "run"), 0o700)
	os.WriteFile(filepath.Join(dir, "run", "egress.json"), append(b, '\n'), 0o600)
	if got := SweepStale(dir); len(got) != 1 || got[0] != ServiceEgress {
		t.Fatalf("stale not cleaned: %v", got)
	}
	// Live file survives.
	if got := SweepStale(dir); len(got) != 0 {
		t.Fatalf("live file swept: %v", got)
	}
	if err := RemoveRunFile(dir, ServiceMCP); err != nil {
		t.Fatal(err)
	}
}
