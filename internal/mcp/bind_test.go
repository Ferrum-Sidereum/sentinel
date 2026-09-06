package mcp

import (
	"bytes"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"sentinel/internal/audit"
	"sentinel/internal/policy"
	"sentinel/internal/scrubber"
	"sentinel/internal/vault"
)

func testVaultWithHosts(t *testing.T, sec vault.Secret) *vault.Store {
	t.Helper()
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i + 7)
	}
	st, err := vault.Open(filepath.Join(t.TempDir(), "v.db"), key)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	if err := st.Put(sec); err != nil {
		t.Fatal(err)
	}
	return st
}

func TestBindRefusedNoDest(t *testing.T) {
	st := testVaultWithHosts(t, vault.Secret{Name: "gh", Value: []byte("v"), Hosts: []string{"api.github.com"}})
	p := policy.Default()
	p.Approvals.Default = "allow"
	Strict = true
	defer func() { Strict = false }()
	t.Setenv("SNT_BIND_T", "snt://gh")
	l, _ := audit.Open(filepath.Join(t.TempDir(), "a.jsonl"))
	defer l.Close()
	err := RunWithOptions([]string{"--", "go", "version"}, ModeInject, RunOptions{}, st, &p, l, scrubber.NewSession(time.Hour))
	ee, ok := err.(*ExitError)
	if !ok {
		t.Fatalf("want ExitError bind refusal, got %T %v", err, err)
	}
	if _, ok := ee.Err.(*BindError); !ok {
		t.Fatalf("want *BindError, got %T %v", ee.Err, ee.Err)
	}
}

func TestBindAllowedMatchingDest(t *testing.T) {
	st := testVaultWithHosts(t, vault.Secret{Name: "gh", Value: []byte("v"), Hosts: []string{"api.github.com"}})
	p := policy.Default()
	p.Approvals.Default = "allow"
	t.Setenv("SNT_BIND_T", "snt://gh")
	l, _ := audit.Open(filepath.Join(t.TempDir(), "a.jsonl"))
	defer l.Close()
	if err := RunWithOptions([]string{"--", "go", "version"}, ModeInject, RunOptions{Dests: []string{"api.github.com"}}, st, &p, l, scrubber.NewSession(time.Hour)); err != nil {
		if ee, ok := err.(*ExitError); ok {
			if _, isBind := ee.Err.(*BindError); isBind {
				t.Fatalf("matching dest must allow: %v", err)
			}
		}
	}
}

func TestBindWildcardNeedsFlag(t *testing.T) {
	st := testVaultWithHosts(t, vault.Secret{Name: "w", Value: []byte("v"), Hosts: []string{"*"}})
	p := policy.Default()
	p.Approvals.Default = "allow"
	Strict = true
	defer func() { Strict = false }()
	t.Setenv("SNT_BIND_T", "snt://w")
	l, _ := audit.Open(filepath.Join(t.TempDir(), "a.jsonl"))
	defer l.Close()
	if err := RunWithOptions([]string{"--", "go", "version"}, ModeInject, RunOptions{Dests: []string{"x.com"}}, st, &p, l, scrubber.NewSession(time.Hour)); err == nil {
		t.Fatal("wildcard without --allow-unbound must refuse")
	}
	if err := RunWithOptions([]string{"--", "go", "version"}, ModeInject, RunOptions{Dests: []string{"x.com"}, AllowUnbound: true}, st, &p, l, scrubber.NewSession(time.Hour)); err != nil {
		if ee, ok := err.(*ExitError); ok {
			if _, isBind := ee.Err.(*BindError); isBind {
				t.Fatalf("wildcard with flag must allow: %v", err)
			}
		}
	}
}

func TestBrokerModeE2E(t *testing.T) {
	st := testVaultWithHosts(t, vault.Secret{Name: "tok", Value: []byte("real-value")})
	p := policy.Default()
	p.Approvals.Default = "allow"
	l, _ := audit.Open(filepath.Join(t.TempDir(), "a.jsonl"))
	defer l.Close()
	br := defaultBrokerFor(&p, l)
	url, stop, err := ServeBroker(br, st, l, "mcp:test:stub")
	if err != nil {
		t.Fatal(err)
	}
	defer stop()
	body, _ := json.Marshal(map[string]string{"secret": "tok", "dest": "stub"})
	resp, err := http.Post(url+"/resolve", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("broker resolve status = %d", resp.StatusCode)
	}
	var buf bytes.Buffer
	if _, err := buf.ReadFrom(resp.Body); err != nil {
		t.Fatal(err)
	}
	if buf.String() != "real-value" {
		t.Fatalf("broker value = %q", buf.String())
	}
	// Placeholders stay in child env: run stub that prints env.
	t.Setenv("SNT_BROKER_T", "snt://tok")
	if err := RunWithOptions([]string{"--", "go", "version"}, ModeBroker, RunOptions{}, st, &p, l, scrubber.NewSession(time.Hour)); err != nil {
		t.Fatal(err)
	}
	var _ = os.Environ
}
