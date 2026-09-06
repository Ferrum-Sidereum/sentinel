package mcp

import (
	"path/filepath"
	"testing"
	"time"

	"sentinel/internal/audit"
	"sentinel/internal/policy"
	"sentinel/internal/scrubber"
	"sentinel/internal/vault"
)

func testVault(t *testing.T, secrets map[string]string) *vault.Store {
	t.Helper()
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i + 1)
	}
	st, err := vault.Open(filepath.Join(t.TempDir(), "v.db"), key)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	for n, v := range secrets {
		b := []byte(v)
		if err := st.Put(vault.Secret{Name: n, Value: b}); err != nil {
			t.Fatal(err)
		}
	}
	return st
}

// TestInjectDenyLeavesPlaceholder: default deny => strict run exits 4.
func TestInjectDenyStrict(t *testing.T) {
	st := testVault(t, map[string]string{"github_token": "real-value"})
	p := policy.Default()
	p.Approvals.Default = "deny"
	Strict = true
	defer func() { Strict = false }()
	t.Setenv("SNT_TEST_TOKEN", "snt://github_token")
	l, err := audit.Open(filepath.Join(t.TempDir(), "a.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	sess := scrubber.NewSession(time.Hour)
	err = RunWithMode([]string{"--", "go", "version"}, ModeInject, st, &p, l, sess)
	ee, ok := err.(*ExitError)
	if !ok {
		t.Fatalf("strict deny must return ExitError, got %T %v", err, err)
	}
	if ee.Code != 4 {
		t.Fatalf("exit code must be 4, got %d", ee.Code)
	}
}

// TestInjectAllowRule: matching allow rule resolves the placeholder.
func TestInjectAllowRule(t *testing.T) {
	st := testVault(t, map[string]string{"github_token": "real-value"})
	p := policy.Default()
	p.Approvals.Default = "deny"
	p.Approvals.Rules = []policy.ApprovalRule{
		{Name: "dev-github", Secret: "github_token", Consumer: "mcp::*", Decision: "allow"},
	}
	l, err := audit.Open(filepath.Join(t.TempDir(), "a.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	t.Setenv("SNT_TEST_TOKEN", "snt://github_token")
	sess := scrubber.NewSession(time.Hour)
	// non-strict: must not error even though child runs; just verify no exit-4
	if err := RunWithMode([]string{"--", "go", "version"}, ModeInject, st, &p, l, sess); err != nil {
		if ee, ok := err.(*ExitError); ok && ee.Code == 4 {
			t.Fatalf("allow rule must not deny: %v", err)
		}
	}
}
