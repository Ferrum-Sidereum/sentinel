package mcp

import (
	"encoding/json"
	"os"
	"strings"
	"testing"

	"sentinel/internal/policy"
)

func profileTestPolicy() *policy.Policy {
	p := policy.Default()
	p.Profiles = map[string]policy.Profile{
		"a": {DenyTools: []string{"shell"}},
		"b": {AllowTools: []string{"read"}},
	}
	p.Entities["mcp:deny:shell"] = struct {
		ToLLM       string   `yaml:"to_llm"`
		ToUntrusted string   `yaml:"to_untrusted"`
		Detector    []string `yaml:"detector"`
	}{ToLLM: "block", ToUntrusted: "block"}
	return &p
}

func TestProfileToolDeniedAAllowedDefault(t *testing.T) {
	p := profileTestPolicy()
	deny, err := p.ResolveProfile("a")
	if err != nil {
		t.Fatal(err)
	}
	line := `{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"shell","arguments":{}}}`
	if f := checkInboundProfile(line, deny, p, "a"); len(f) == 0 {
		t.Fatal("profile a must deny shell")
	}
	denyB, err := p.ResolveProfile("b")
	if err != nil {
		t.Fatal(err)
	}
	lineB := `{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"read","arguments":{}}}`
	if f := checkInboundProfile(lineB, denyB, p, "b"); len(f) != 0 {
		t.Fatalf("profile b must allow read: %v", f)
	}
}

func TestAllowlistDeniesUnlisted(t *testing.T) {
	p := profileTestPolicy()
	deny, _ := p.ResolveProfile("b")
	line := `{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"shell","arguments":{}}}`
	if f := checkInboundProfile(line, deny, p, "b"); len(f) == 0 {
		t.Fatal("allowlist must deny unlisted tool")
	}
}

func TestLegacyDenyNotConsulted(t *testing.T) {
	p := profileTestPolicy()
	// default profile: legacy mcp:deny:shell must NOT block
	deny, _ := p.ResolveProfile("")
	line := `{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"shell","arguments":{}}}`
	if f := checkInboundProfile(line, deny, p, ""); len(f) != 0 {
		t.Fatalf("legacy keys must be ignored: %v", f)
	}
	if len(p.LegacyDenyTools()) == 0 {
		t.Fatal("legacy keys must still be detected for warning")
	}
}

func TestDenyCoversReadAndPrompt(t *testing.T) {
	deny := map[string]bool{"resource:file:///x": true, "prompt:p1": true}
	r := `{"jsonrpc":"2.0","id":1,"method":"resources/read","params":{"uri":"file:///x"}}`
	if f := checkInbound(r, deny); len(f) == 0 {
		t.Fatal("resources/read deny not triggered")
	}
	g := `{"jsonrpc":"2.0","id":2,"method":"prompts/get","params":{"name":"p1"}}`
	if f := checkInbound(g, deny); len(f) == 0 {
		t.Fatal("prompts/get deny not triggered")
	}
}

func TestUnknownProfileError(t *testing.T) {
	p := profileTestPolicy()
	if _, err := p.ResolveProfile("nope"); !policy.IsUnknownProfile(err) {
		t.Fatalf("want unknown profile, got %v", err)
	}
}

func TestDenialCarriesRequestID(t *testing.T) {
	f, err := os.CreateTemp("", "denial*.json")
	if err != nil {
		t.Fatal(err)
	}
	name := f.Name()
	f.Close()
	defer os.Remove(name)
	w, err := os.OpenFile(name, os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	writeErr(w, 42, "tool denied: shell")
	w.Close()
	b, _ := os.ReadFile(name)
	var m struct {
		ID    any `json:"id"`
		Error struct {
			Code    int    `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	if m.ID == nil || m.Error.Code != -32602 || !strings.Contains(m.Error.Message, "shell") {
		t.Fatalf("malformed denial: %s", strings.TrimSpace(string(b)))
	}
	if id, ok := m.ID.(float64); !ok || id != 42 {
		t.Fatalf("id must be request id 42, got %v", m.ID)
	}
}
