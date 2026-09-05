package keyring

import (
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/zalando/go-keyring"
)

type fakeStore struct {
	val      string
	getErr   error
	setErr   error
	setCalls int
	lastSet  string
}

func (f *fakeStore) Get(_, _ string) (string, error) {
	if f.getErr != nil {
		return "", f.getErr
	}
	return f.val, nil
}

func (f *fakeStore) Set(_, _, pw string) error {
	f.setCalls++
	f.lastSet = pw
	return f.setErr
}

func withStore(s credentialStore, fn func()) {
	old := store
	store = s
	defer func() { store = old }()
	fn()
}

func TestLoadRoundTrip(t *testing.T) {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}
	withStore(&fakeStore{val: hex.EncodeToString(key)}, func() {
		got, err := Load()
		if err != nil {
			t.Fatal(err)
		}
		if hex.EncodeToString(got) != hex.EncodeToString(key) {
			t.Fatal("mismatch")
		}
	})
}

func TestLoadNotFound(t *testing.T) {
	withStore(&fakeStore{getErr: keyring.ErrNotFound}, func() {
		if _, err := Load(); !errors.Is(err, ErrNotFound) {
			t.Fatalf("want ErrNotFound, got %v", err)
		}
	})
}

func TestLoadTransportErrorNoWrite(t *testing.T) {
	f := &fakeStore{getErr: errors.New("dbus down")}
	withStore(f, func() {
		if _, err := Load(); !errors.Is(err, ErrUnavailable) {
			t.Fatalf("want ErrUnavailable, got %v", err)
		}
	})
	if f.setCalls != 0 {
		t.Fatal("must not write on transport error")
	}
}

func TestLoadBadHex(t *testing.T) {
	for _, v := range []string{"abc", "zz" + string(make([]byte, 62))} {
		withStore(&fakeStore{val: v}, func() {
			if _, err := Load(); !errors.Is(err, ErrUnavailable) {
				t.Fatalf("want ErrUnavailable for %q, got %v", v, err)
			}
		})
	}
}

func TestCreateRefusesExistingVault(t *testing.T) {
	for _, name := range []string{"vault.db", "passphrase"} {
		dir := t.TempDir()
		os.WriteFile(filepath.Join(dir, name), []byte("x"), 0o600)
		f := &fakeStore{getErr: keyring.ErrNotFound}
		withStore(f, func() {
			if _, err := Create(dir); !errors.Is(err, ErrVaultExists) {
				t.Fatalf("%s: want ErrVaultExists, got %v", name, err)
			}
		})
		if f.setCalls != 0 {
			t.Fatalf("%s: keychain must not be written", name)
		}
	}
}

func TestCreateWritesNewKey(t *testing.T) {
	dir := t.TempDir()
	f := &fakeStore{getErr: keyring.ErrNotFound}
	withStore(f, func() {
		key, err := Create(dir)
		if err != nil {
			t.Fatal(err)
		}
		if len(key) != 32 {
			t.Fatal("want 32 bytes")
		}
		if f.setCalls != 1 || f.lastSet != hex.EncodeToString(key) {
			t.Fatal("keychain write mismatch")
		}
	})
}

func TestHexRejects(t *testing.T) {
	if _, err := hex.DecodeString("abc"); err == nil {
		t.Fatal("odd length must fail")
	}
	if _, err := hex.DecodeString("zz"); err == nil {
		t.Fatal("non-hex must fail")
	}
}
