package main

import (
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"sentinel/internal/audit"
	"sentinel/internal/egress"
	"sentinel/internal/llm"
	"sentinel/internal/policy"
	"sentinel/internal/runtime"
)

func TestDefaultGatewaysNoCollision(t *testing.T) {
	p := policy.Default()
	a, err := egress.Serve("127.0.0.1:0", nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer a.Stop()
	g, err := llm.Serve("127.0.0.1:0", "http://127.0.0.1:1", &p, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer g.Stop()
	if a.Addr == g.Addr {
		t.Fatal("gateways collided")
	}
	for _, addr := range []string{a.Addr, g.Addr} {
		c, err := net.Dial("tcp", addr)
		if err != nil {
			t.Fatalf("dial %s: %v", addr, err)
		}
		c.Close()
	}
}

func TestPortZeroPrintsParseableAddr(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	ln.Close()
	if _, _, err := net.SplitHostPort(addr); err != nil {
		t.Fatalf("unparseable addr %q: %v", addr, err)
	}
	if err := runtime.DialConnect("127.0.0.1:1"); err == nil {
		t.Log("note: port 1 unexpectedly open")
	}
}

func TestStatusJSONShape(t *testing.T) {
	out, _, code := cliHarness(t, []string{"status", "--json"}, "")
	if code != 0 {
		t.Fatalf("status exit %d", code)
	}
	var rep map[string]any
	if err := json.Unmarshal([]byte(out), &rep); err != nil {
		t.Fatalf("status not JSON: %v %q", err, out)
	}
	for _, k := range []string{"gateways", "vault_path", "key_source", "secret_count", "expired_count"} {
		if _, ok := rep[k]; !ok {
			t.Fatalf("status missing %s: %q", k, out)
		}
	}
}

func TestSigtermCleanShutdown(t *testing.T) {
	dd := t.TempDir()
	af, err := os.OpenFile(filepath.Join(dd, "audit.jsonl"), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	af.WriteString("{\"time\":\"t\",\"type\":\"start\"}\n")
	_ = af.Close()
	l, err := audit.Open(filepath.Join(dd, "audit.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	if err := runtime.WriteRunFile(dd, runtime.ServiceLLM, addr, "dev"); err != nil {
		t.Fatal(err)
	}
	sess := &serveSession{dataDir: dd, service: runtime.ServiceLLM, audit: l, stop: func() { _ = ln.Close() }}
	if code := runServeLoop("llm gateway on "+addr, sess, func() {}); code != 0 {
		t.Fatalf("exit %d", code)
	}
	if _, err := os.Stat(filepath.Join(dd, "run", "llm.json")); !os.IsNotExist(err) {
		t.Fatal("run file not removed")
	}
	raw, err := os.ReadFile(filepath.Join(dd, "audit.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(string(raw)), "\n")
	var last map[string]any
	if err := json.Unmarshal([]byte(lines[len(lines)-1]), &last); err != nil {
		t.Fatalf("audit last line not full JSON: %v", err)
	}
}
