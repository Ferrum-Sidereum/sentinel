package keyring

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"

	"github.com/zalando/go-keyring"
)

const service = "sentinel-master"

var (
	ErrNotFound    = errors.New("keyring: no master key")
	ErrUnavailable = errors.New("keyring: credential store unavailable")
	ErrVaultExists = errors.New("keyring: vault data exists without a matching key")
)

// credentialStore abstracts the OS keychain for testing.
type credentialStore interface {
	Get(service, user string) (string, error)
	Set(service, user, password string) error
}

type osStore struct{}

func (osStore) Get(service, user string) (string, error) { return keyring.Get(service, user) }
func (osStore) Set(service, user, password string) error {
	return keyring.Set(service, user, password)
}

var store credentialStore = osStore{}

// Load returns the existing master key. It never creates one.
func Load() ([]byte, error) {
	k, err := store.Get(service, "master")
	if err != nil {
		if errors.Is(err, keyring.ErrNotFound) {
			return nil, ErrNotFound
		}
		return nil, ErrUnavailable
	}
	raw, err := hex.DecodeString(k)
	if err != nil || len(raw) != 32 {
		return nil, ErrUnavailable
	}
	key := make([]byte, 32)
	copy(key, raw)
	return key, nil
}

// Create generates and stores a new master key.
// It returns ErrVaultExists if any vault artifact is present in dir.
func Create(dir string) ([]byte, error) {
	for _, name := range []string{"vault.db", "passphrase"} {
		if _, err := os.Stat(filepath.Join(dir, name)); err == nil {
			return nil, ErrVaultExists
		}
	}
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return nil, err
	}
	if err := store.Set(service, "master", hex.EncodeToString(key)); err != nil {
		return nil, ErrUnavailable
	}
	return key, nil
}

// Remediation text for ErrUnavailable.
const Remediation = "credential store unavailable: unlock your OS keychain and retry `sentinel init`"
