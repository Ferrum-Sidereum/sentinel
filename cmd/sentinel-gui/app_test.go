package main

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sentinel/internal/keyring"
	"sentinel/internal/vault"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

type fakeKeys struct {
	key     []byte
	loadErr error
	creates int
}

func (f *fakeKeys) load() ([]byte, error) {
	if f.loadErr != nil {
		return nil, f.loadErr
	}
	out := make([]byte, len(f.key))
	copy(out, f.key)
	return out, nil
}

func (f *fakeKeys) create(dir string) ([]byte, error) {
	f.creates++
	out := make([]byte, len(f.key))
	copy(out, f.key)
	return out, nil
}

func testApp(t *testing.T) *App {
	t.Helper()
	fk := &fakeKeys{key: bytes.Repeat([]byte{0xab}, 32)}
	return &App{dir: t.TempDir(), keyLoad: fk.load, keyCreate: fk.create}
}

func TestNeverRekeysExistingVault(t *testing.T) {
	for _, file := range []string{"vault.db", "passphrase"} {
		t.Run(file, func(t *testing.T) {
			dir := t.TempDir()
			if err := os.WriteFile(filepath.Join(dir, file), []byte("existing"), 0600); err != nil {
				t.Fatal(err)
			}
			fk := &fakeKeys{loadErr: keyring.ErrNotFound}
			a := &App{dir: dir, keyLoad: fk.load, keyCreate: fk.create}
			if _, _, err := a.openStore(); err == nil {
				t.Fatal("expected refusal")
			}
			if fk.creates != 0 {
				t.Fatal("credential overwritten")
			}
		})
	}
}

func TestInvalidOrUnavailableKeyIsNotReplaced(t *testing.T) {
	for _, loadErr := range []error{keyring.ErrUnavailable, errors.New("locked")} {
		fk := &fakeKeys{loadErr: loadErr}
		a := &App{dir: t.TempDir(), keyLoad: fk.load, keyCreate: fk.create}
		if _, _, err := a.openStore(); err == nil {
			t.Fatal("expected refusal")
		}
		if fk.creates != 0 {
			t.Fatal("unexpected credential write")
		}
	}
}

func TestNewProfileCreatesKeyOnce(t *testing.T) {
	fk := &fakeKeys{loadErr: keyring.ErrNotFound, key: bytes.Repeat([]byte{7}, 32)}
	a := &App{dir: t.TempDir(), keyLoad: fk.load, keyCreate: fk.create}
	st, key, err := a.openStore()
	if err != nil {
		t.Fatal(err)
	}
	closeStore(st, key)
	if fk.creates != 1 {
		t.Fatal("key not created once")
	}
	// Second open uses the stored key (no second create).
	fk.loadErr = nil
	st2, key2, err := a.openStore()
	if err != nil {
		t.Fatal(err)
	}
	closeStore(st2, key2)
	if fk.creates != 1 {
		t.Fatal("key created twice")
	}
}

func TestSecretCRUDDoesNotRevealOrOverwrite(t *testing.T) {
	a := testApp(t)
	rows, err := a.AddSecretBound("demo", "synthetic-sensitive-value", "example.test", nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	payload, _ := json.Marshal(rows)
	if bytes.Contains(payload, []byte("synthetic-sensitive-value")) {
		t.Fatal("plaintext crossed bridge")
	}
	if rows[0].Placeholder != "snt://demo" {
		t.Fatalf("placeholder: %q", rows[0].Placeholder)
	}
	if _, err := a.AddSecretBound("demo", "different", "example.test", nil, nil, nil); err == nil {
		t.Fatal("duplicate overwritten")
	}
	if _, err := a.DeleteSecret("demo", "wrong"); err == nil {
		t.Fatal("confirmation bypass")
	}
	rows, err = a.DeleteSecret("demo", "demo")
	if err != nil || len(rows) != 0 {
		t.Fatalf("delete: %v", err)
	}
}

func TestRevealRequiresConfirmationAndAudits(t *testing.T) {
	a := testApp(t)
	if _, err := a.AddSecretBound("demo", "synthetic-sensitive-value", "example.test", nil, nil, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := a.RevealSecret("demo", "wrong"); err == nil {
		t.Fatal("confirmation bypass")
	}
	v, err := a.RevealSecret("demo", "demo")
	if err != nil || v != "synthetic-sensitive-value" {
		t.Fatalf("reveal: %v", err)
	}
	raw, err := os.ReadFile(filepath.Join(a.dir, "audit.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(raw, []byte("secret_revealed")) {
		t.Fatal("reveal not audited")
	}
	if bytes.Contains(raw, []byte("synthetic-sensitive-value")) {
		t.Fatal("audit contains value")
	}
}

func TestPreservesExistingHostBindingMetadata(t *testing.T) {
	a := testApp(t)
	st, key, err := a.openStore()
	if err != nil {
		t.Fatal(err)
	}
	if err := st.Put(vault.Secret{Name: "bound", Value: []byte("synthetic-bound"), Hosts: []string{"example.test"}, InjectHdr: []string{"Authorization"}}); err != nil {
		t.Fatal(err)
	}
	closeStore(st, key)
	if _, err := a.AddSecretBound("BOUND", "replacement", "example.test", nil, nil, nil); err == nil {
		t.Fatal("duplicate should fail")
	}
	st, key, err = a.openStore()
	if err != nil {
		t.Fatal(err)
	}
	defer closeStore(st, key)
	sec, err := st.Get("bound")
	if err != nil {
		t.Fatal(err)
	}
	if len(sec.Hosts) != 1 || sec.Hosts[0] != "example.test" || string(sec.Value) != "synthetic-bound" {
		t.Fatal("metadata changed")
	}
	wipe(sec.Value)
}

func TestWrongKeyFailsSnapshot(t *testing.T) {
	a := testApp(t)
	if _, err := a.AddSecretBound("demo", "synthetic", "example.test", nil, nil, nil); err != nil {
		t.Fatal(err)
	}
	bad := &fakeKeys{key: bytes.Repeat([]byte{1}, 32)}
	a.keyLoad = bad.load
	if _, err := a.Snapshot(); err == nil {
		t.Fatal("wrong key accepted")
	}
}

func TestScanResultNeverContainsMatchedValues(t *testing.T) {
	a := testApp(t)
	if _, err := a.AddSecretBound("demo", "unique-test-value-123", "example.test", nil, nil, nil); err != nil {
		t.Fatal(err)
	}
	result, err := a.Scan("contact demo@example.test; unique-test-value-123")
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Findings) == 0 {
		t.Fatal("expected findings")
	}
	raw, _ := json.Marshal(result)
	for _, forbidden := range []string{"demo@example.test", "unique-test-value-123", "snt://demo"} {
		if bytes.Contains(raw, []byte(forbidden)) {
			t.Fatal("sensitive value crossed bridge")
		}
	}
}

func TestScanLimitsAndBusy(t *testing.T) {
	a := testApp(t)
	for _, input := range []string{"", strings.Repeat("x", maxScanBytes+1), string([]byte{0xff})} {
		if _, err := a.Scan(input); err == nil {
			t.Fatal("invalid input accepted")
		}
	}
	a.mu.Lock()
	if _, err := a.Snapshot(); err == nil {
		t.Fatal("concurrent operation accepted")
	}
	a.mu.Unlock()
}

func TestPolicyRevisionAndExtensions(t *testing.T) {
	a := testApp(t)
	path := filepath.Join(a.dir, "policy.yaml")
	original := []byte("extension: keep-me\nentities:\n  EMAIL:\n    to_llm: mask\n    detector: [regex]\n    future_setting: keep-too\nhosts:\n  example.test:\n    class: trusted\n")
	if err := os.WriteFile(path, original, 0600); err != nil {
		t.Fatal(err)
	}
	snapshot, err := a.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := a.SavePolicy("stale", snapshot.Policy.Entities, nil); err == nil {
		t.Fatal("stale write accepted")
	}
	for i := range snapshot.Policy.Entities {
		if snapshot.Policy.Entities[i].Name == "EMAIL" {
			snapshot.Policy.Entities[i].ToLLM = "block"
		}
	}
	saved, err := a.SavePolicy(snapshot.Policy.Revision, snapshot.Policy.Entities, []PatternInfo{{Name: "custom", Expression: `TEST-[0-9]+`}})
	if err != nil {
		t.Fatal(err)
	}
	if saved.Revision == snapshot.Policy.Revision {
		t.Fatal("revision unchanged")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var p map[string]interface{}
	if err := yaml.Unmarshal(raw, &p); err != nil {
		t.Fatal(err)
	}
	if p["extension"] != "keep-me" || !bytes.Contains(raw, []byte("keep-too")) || !bytes.Contains(raw, []byte("example.test")) {
		t.Fatal("policy extensions lost")
	}
	backups, _ := filepath.Glob(path + ".bak-*")
	if len(backups) != 1 {
		t.Fatal("expected policy backup")
	}
	backup, _ := os.ReadFile(backups[0])
	if !bytes.Equal(backup, original) {
		t.Fatal("backup is not original bytes")
	}
	if _, err := a.SavePolicy(saved.Revision, saved.Entities, []PatternInfo{{Name: "bad", Expression: "["}}); err == nil {
		t.Fatal("invalid regex accepted")
	}
}

func TestCustomPatternsAreActuallyUsed(t *testing.T) {
	a := testApp(t)
	snap, err := a.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := a.SavePolicy(snap.Policy.Revision, snap.Policy.Entities, []PatternInfo{{Name: "internal_id", Expression: `TICKET-[0-9]{4}`}}); err != nil {
		t.Fatal(err)
	}
	scan, err := a.Scan("TICKET-1234")
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, f := range scan.Findings {
		if f.Category == "internal_id" && f.Detector == "custom" {
			found = true
		}
	}
	if !found {
		t.Fatal("custom pattern not applied")
	}
}

func TestAuditProjectionDropsUnknownMetadata(t *testing.T) {
	a := testApp(t)
	line := `{"time":"2026-09-05T21:00:00Z","type":"pii_redacted","fields":{"count":2,"value":"SYNTHETIC_SECRET","path":"private"}}` + "\n"
	line += `{"time":"2026-09-05T21:01:00Z","type":"SYNTHETIC_SECRET","fields":{"count":-1}}` + "\n"
	line += "not-json\n"
	if err := os.WriteFile(filepath.Join(a.dir, "audit.jsonl"), []byte(line), 0600); err != nil {
		t.Fatal(err)
	}
	page, err := a.Activity()
	if err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(page)
	if bytes.Contains(b, []byte("SYNTHETIC_SECRET")) || bytes.Contains(b, []byte("private")) {
		t.Fatal("audit leakage")
	}
	if len(page.Rows) != 2 || page.Skipped != 1 || page.Rows[0].Type != "legacy.event" {
		t.Fatal("unexpected audit projection")
	}
}

func TestAuditWindowIsBounded(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	line := `{"time":"2026-09-05T21:00:00Z","type":"pii_redacted","fields":{"count":1}}` + "\n"
	if err := os.WriteFile(path, []byte(strings.Repeat(line, 5000)), 0600); err != nil {
		t.Fatal(err)
	}
	page, err := readActivity(path)
	if err != nil {
		t.Fatal(err)
	}
	if !page.Truncated || len(page.Rows) != 100 {
		t.Fatal("unbounded audit page")
	}
}

// hex import is used by pattern tests historically; keep referenced.
var _ = hex.EncodeToString
