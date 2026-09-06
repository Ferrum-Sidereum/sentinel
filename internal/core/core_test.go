package core

import (
	"bytes"
	"strings"
	"testing"

	"sentinel/internal/policy"
	"sentinel/internal/vault"
)

func openTestStore(t *testing.T) *vault.Store {
	t.Helper()
	dir := t.TempDir()
	st, err := OpenWithKey(dir, bytes.Repeat([]byte{9}, 32))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	return st
}

// Shared normalisation fixture: CLI/env-import/GUI must agree.
func TestNormalizeSharedFixture(t *testing.T) {
	cases := []struct{ in, want string }{
		{"API-Token", "api_token"},
		{"my secret", "my_secret"},
		{"GITHUB_PAT", "github_pat"},
		{"a", "a"},
		{strings.Repeat("x", 64), strings.Repeat("x", 64)},
	}
	for _, c := range cases {
		got, err := NormalizeName(c.in)
		if err != nil || got != c.want {
			t.Fatalf("NormalizeName(%q) = %q, %v; want %q", c.in, got, err, c.want)
		}
	}
	for _, bad := range []string{"", "has.dot", "snt://x", strings.Repeat("y", 65), "a/b", "tab\tname"} {
		if n, err := NormalizeName(bad); err == nil {
			t.Fatalf("NormalizeName(%q) = %q, want error", bad, n)
		}
	}
	if got, err := NormalizeName("UPPER OK"); err != nil || got != "upper_ok" {
		t.Fatalf("NormalizeName(UPPER OK) = %q, %v", got, err)
	}
}

// GUI-adapter path: secret created via core.Add with hosts resolves through
// the same vault matcher the egress proxy uses (shouldMITM/scrubEcho).
func TestGUIAdapterSecretResolvesInProxy(t *testing.T) {
	st := openTestStore(t)
	if err := Add(st, AddInput{Name: "Gui-Token", Value: []byte("synthetic-gui-value"), Hosts: []string{"example.test"}, InjectHdr: []string{"Authorization"}}); err != nil {
		t.Fatal(err)
	}
	sec, err := Get(st, "gui_token")
	if err != nil {
		t.Fatal(err)
	}
	if len(sec.Hosts) != 1 || sec.Hosts[0] != "example.test" {
		t.Fatalf("hosts = %v", sec.Hosts)
	}
	for i := range sec.Value {
		sec.Value[i] = 0
	}
	m, err := st.NewMatcher()
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	got := m.FindAll("leaked synthetic-gui-value here")
	if len(got) != 1 || got[0].Name != "gui_token" {
		t.Fatalf("matcher = %+v", got)
	}
}

func TestPolicyWholeStructRoundTrip(t *testing.T) {
	raw := []byte("# top comment\ndefaults:\n  unknown_host: tunnel # keep\n  scrub_to_llm: pseudonymize\nhosts:\n  example.test: # host comment\n    class: trusted\n    scan_response: true\nentities:\n  EMAIL:\n    to_llm: mask\n    detector: [regex]\n    future_setting: keep-too # entity comment\nfuture_top: keep-me\n")
	p := policy.Default()
	p.Hosts = map[string]policy.HostRule{"example.test": {Class: "untrusted", ScanResponse: true}}
	out, err := UpdatePolicyDocument(raw, p)
	if err != nil {
		t.Fatal(err)
	}
	s := string(out)
	for _, want := range []string{"# top comment", "# keep", "# host comment", "# entity comment", "future_setting", "keep-too", "future_top", "keep-me", "example.test"} {
		if !strings.Contains(s, want) {
			t.Fatalf("round-trip lost %q:\n%s", want, s)
		}
	}
	if !strings.Contains(s, "untrusted") {
		t.Fatalf("edited value missing:\n%s", s)
	}
}

func TestAddListRotateRemove(t *testing.T) {
	dir := t.TempDir()
	st, err := OpenWithKey(dir, bytes.Repeat([]byte{3}, 32))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if err := Add(st, AddInput{Name: "svc", Value: []byte("v1"), Hosts: []string{"h.test"}}); err != nil {
		t.Fatal(err)
	}
	names, err := List(st)
	if err != nil || len(names) != 1 || names[0] != "svc" {
		t.Fatalf("list = %v, %v", names, err)
	}
	if err := Rotate(st, "svc", []byte("v2"), 3); err != nil {
		t.Fatal(err)
	}
	sec, err := Get(st, "svc")
	if err != nil || string(sec.Value) != "v2" {
		t.Fatalf("get after rotate: %v %v", sec.Value, err)
	}
	for i := range sec.Value {
		sec.Value[i] = 0
	}
	if err := Remove(st, "svc"); err != nil {
		t.Fatal(err)
	}
	if _, err := Get(st, "svc"); err == nil {
		t.Fatal("expected error after remove")
	}
}
