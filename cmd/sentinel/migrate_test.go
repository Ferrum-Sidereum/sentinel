package main

import (
	"os"
	"path/filepath"
	"testing"

	"sentinel/internal/keyring"
	"sentinel/internal/vault"
)

// Fixture test (I9): legacy layout (raw passphrase file + vault encrypted
// under the legacy KDF) migrates to key.json; old file deleted only after
// verified read under the new key.
func TestMigrateLegacyFixture(t *testing.T) {
	dir := t.TempDir()
	legacy := []byte("legacy-passphrase\n")
	if err := os.WriteFile(filepath.Join(dir, "passphrase"), legacy, 0o600); err != nil {
		t.Fatal(err)
	}
	oldKey := keyring.DeriveLegacy(legacy)
	st, err := vault.Open(filepath.Join(dir, "vault.db"), oldKey)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.Put(vault.Secret{Name: "api", Value: []byte("s3cr3t")}); err != nil {
		t.Fatal(err)
	}
	st.Close()

	prompt := func() ([]byte, error) { return []byte("new-passphrase"), nil }
	if err := migrateLegacy(dir, prompt); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, "passphrase")); !os.IsNotExist(err) {
		t.Fatal("legacy passphrase file not deleted")
	}
	newKey, err := keyring.OpenPassphrase(dir, []byte("new-passphrase"))
	if err != nil {
		t.Fatal(err)
	}
	st2, err := vault.Open(filepath.Join(dir, "vault.db"), newKey)
	if err != nil {
		t.Fatal(err)
	}
	defer st2.Close()
	sec, err := st2.Get("api")
	if err != nil {
		t.Fatal(err)
	}
	if string(sec.Value) != "s3cr3t" {
		t.Fatalf("migrated secret mismatch: %q", sec.Value)
	}
}
