package policy

import (
	"os"
	"path/filepath"
	"testing"
)

func writeProfilePolicy(t *testing.T) string {
	t.Helper()
	doc := `profiles:
  a:
    deny_tools: [shell]
  b:
    allow_tools: [read]
  c:
    deny_tools: []
entities:
  mcp:deny:shell:
    to_llm: block
    to_untrusted: block
`
	p := filepath.Join(t.TempDir(), "policy.yaml")
	if err := os.WriteFile(p, []byte(doc), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestProfileDenyDiffers(t *testing.T) {
	pol, err := Load(writeProfilePolicy(t))
	if err != nil {
		t.Fatal(err)
	}
	okA, err := pol.ProfileAllows("a", "shell")
	if err != nil || okA {
		t.Fatalf("a must deny shell: %v %v", okA, err)
	}
	okB, err := pol.ProfileAllows("b", "read")
	if err != nil || !okB {
		t.Fatalf("b must allow read: %v %v", okB, err)
	}
	okB2, err := pol.ProfileAllows("b", "shell")
	if err != nil || okB2 {
		t.Fatalf("b allowlist must deny unlisted shell: %v %v", okB2, err)
	}
	// default profile denies nothing
	if ok, err := pol.ProfileAllows("", "shell"); err != nil || !ok {
		t.Fatalf("default must allow: %v %v", ok, err)
	}
}

func TestUnknownProfile(t *testing.T) {
	pol, err := Load(writeProfilePolicy(t))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pol.ResolveProfile("nope"); !IsUnknownProfile(err) {
		t.Fatalf("want unknown-profile error, got %v", err)
	}
	if _, err := pol.ProfileAllows("nope", "x"); !IsUnknownProfile(err) {
		t.Fatalf("want unknown-profile error, got %v", err)
	}
}

func TestLegacyDenyIgnored(t *testing.T) {
	pol, err := Load(writeProfilePolicy(t))
	if err != nil {
		t.Fatal(err)
	}
	if len(pol.LegacyDenyTools()) == 0 {
		t.Fatal("legacy keys must be detected")
	}
	deny, err := pol.ResolveProfile("")
	if err != nil {
		t.Fatal(err)
	}
	if deny["shell"] {
		t.Fatal("legacy mcp:deny keys must not leak into default profile")
	}
}
