package policy

import (
	"os"
	"path/filepath"
	"testing"
)

func TestApprovalsParse(t *testing.T) {
	yml := `approvals:
  default: ask
  rules:
    - name: dev-github
      secret: github_token
      consumer: "mcp:dev:*"
      dest: api.github.com
      decision: allow
      ttl: 15m
    - secret: "prod_*"
      decision: deny
  grant_cache: 15m
  max_uses_per_minute: 30
`
	dir := t.TempDir()
	p := filepath.Join(dir, "policy.yaml")
	if err := os.WriteFile(p, []byte(yml), 0o600); err != nil {
		t.Fatal(err)
	}
	pol, err := Load(p)
	if err != nil {
		t.Fatal(err)
	}
	if pol.Approvals.Default != "ask" {
		t.Fatalf("default: %q", pol.Approvals.Default)
	}
	if len(pol.Approvals.Rules) != 2 {
		t.Fatalf("rules: %d", len(pol.Approvals.Rules))
	}
	r := pol.Approvals.Rules[0]
	if r.Name != "dev-github" || r.TTLDuration() != 15*60*1000000000 {
		t.Fatalf("rule parse: %+v", r)
	}
	if pol.Approvals.GrantCacheDuration() != 15*60*1000000000 {
		t.Fatal("grant_cache parse")
	}
	if pol.Approvals.MaxUsesPerMinute != 30 {
		t.Fatal("max_uses_per_minute parse")
	}
}

func TestApprovalsBackCompat(t *testing.T) {
	pol, err := Load("")
	if err != nil {
		t.Fatal(err)
	}
	if pol.Approvals.Default != "" || len(pol.Approvals.Rules) != 0 {
		t.Fatalf("default policy must have empty approvals, got %+v", pol.Approvals)
	}
}
