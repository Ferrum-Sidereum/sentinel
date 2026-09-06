package keyring

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestSamePassphraseDifferentKeys(t *testing.T) {
	pw := []byte("correct horse battery staple")
	d1 := t.TempDir()
	d2 := t.TempDir()
	k1, err := CreatePassphrase(d1, pw)
	if err != nil {
		t.Fatal(err)
	}
	k2, err := CreatePassphrase(d2, pw)
	if err != nil {
		t.Fatal(err)
	}
	if string(k1) == string(k2) {
		t.Fatal("same passphrase on two installs derived the same key")
	}
}

func TestWrongPassphraseNamedError(t *testing.T) {
	dir := t.TempDir()
	if _, err := CreatePassphrase(dir, []byte("right")); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenPassphrase(dir, []byte("wrong")); !errors.Is(err, ErrWrongPassphrase) {
		t.Fatalf("expected ErrWrongPassphrase, got %v", err)
	}
}
func TestKeyJSONMode0600(t *testing.T) {
	dir := t.TempDir()
	if _, err := CreatePassphrase(dir, []byte("secret")); err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS == "windows" {
		if aclNarrowCalls == 0 {
			t.Fatal("ACL narrowing helper not invoked on Windows")
		}
		return
	}
	fi, err := os.Stat(filepath.Join(dir, KeyFileName))
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Fatalf("key.json mode = %o, want 600", fi.Mode().Perm())
	}
}
func TestRoundTrip(t *testing.T) {
	dir := t.TempDir()
	k1, err := CreatePassphrase(dir, []byte("pw123"))
	if err != nil {
		t.Fatal(err)
	}
	k2, err := OpenPassphrase(dir, []byte("pw123"))
	if err != nil {
		t.Fatal(err)
	}
	if string(k1) != string(k2) {
		t.Fatal("round-trip key mismatch")
	}
}
