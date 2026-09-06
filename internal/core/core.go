package core

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
	"sentinel/internal/keyring"
	"sentinel/internal/memguard"
	"sentinel/internal/policy"
	"sentinel/internal/vault"
)

// nameRE is the canonical name rule shared by CLI, GUI and env import.
var nameRE = regexp.MustCompile(`^[a-z0-9_]{1,64}$`)

// NormalizeName lowercases, maps '-' and ' ' to '_', then validates.
// Invalid inputs are a clear error, never a silent rewrite.
func NormalizeName(raw string) (string, error) {
	s := strings.ToLower(strings.TrimSpace(raw))
	s = strings.ReplaceAll(strings.ReplaceAll(s, "-", "_"), " ", "_")
	if !nameRE.MatchString(s) {
		return "", fmt.Errorf("invalid secret name %q: use 1-64 chars [a-z0-9_]", raw)
	}
	return s, nil
}

// DataDir resolves state dir: explicit > SENTINEL_DATA_DIR > ~/.sentinel.
func DataDir(explicit string) string {
	if explicit != "" {
		return explicit
	}
	if d := os.Getenv("SENTINEL_DATA_DIR"); d != "" {
		return d
	}
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".sentinel")
}

// Open opens the vault in dir using keyring.Load (never creates).
func Open(dir string) (*vault.Store, error) {
	key, err := keyring.Load()
	if err != nil {
		if errors.Is(err, keyring.ErrUnavailable) {
			return nil, errors.New(keyring.Remediation)
		}
		return nil, err
	}
	defer memguard.Zero(key)
	return vault.Open(filepath.Join(dir, "vault.db"), key)
}

// OpenWithKey is for tests / passphrase flows that already hold a key.
func OpenWithKey(dir string, key []byte) (*vault.Store, error) {
	return vault.Open(filepath.Join(dir, "vault.db"), key)
}

// Init ensures dir + default policy, creates master key if absent.
func Init(dir string) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	def := filepath.Join(dir, "policy.yaml")
	if _, err := os.Stat(def); os.IsNotExist(err) {
		os.WriteFile(def, []byte("defaults:\n  unknown_host: tunnel\n  scrub_to_llm: pseudonymize\n  scrub_to_untrusted: mask\n  confidence_threshold: 0.7\naudit:\n  level: events\n  retention: 30d\n"), 0o600)
	}
	key, err := keyring.Load()
	switch {
	case err == nil:
	case errors.Is(err, keyring.ErrNotFound):
		key, err = keyring.Create(dir)
		if err != nil {
			return err
		}
	case errors.Is(err, keyring.ErrUnavailable):
		return errors.New(keyring.Remediation)
	default:
		return err
	}
	defer memguard.Zero(key)
	st, err := vault.Open(filepath.Join(dir, "vault.db"), key)
	if err != nil {
		return err
	}
	return st.Close()
}

// AddInput carries secret creation fields.
type AddInput struct {
	Name      string
	Value     []byte
	Kind      string
	Hosts     []string
	Paths     []string
	Methods   []string
	InjectHdr []string
	ExpiresAt *time.Time
}

// Add validates the canonical name, then stores. Binding metadata is passed
// through; CLI keeps its current behavior, GUI adapter requires hosts.
func Add(st *vault.Store, in AddInput) error {
	name, err := NormalizeName(in.Name)
	if err != nil {
		return err
	}
	sec := vault.Secret{Name: name, Value: in.Value, Kind: in.Kind, Hosts: in.Hosts, Paths: in.Paths, Methods: in.Methods, InjectHdr: in.InjectHdr, Version: 1, ExpiresAt: in.ExpiresAt}
	if sec.Kind == "" {
		sec.Kind = "bearer"
	}
	return st.Put(sec)
}

// List/Get/Rotate/Remove are thin pass-throughs so both UIs share one path.
func List(st *vault.Store) ([]string, error) { return st.List() }

func Get(st *vault.Store, name string) (vault.Secret, error) { return st.Get(name) }

func Rotate(st *vault.Store, name string, v []byte, keep int) error {
	return st.Rotate(name, v, keep)
}

func Remove(st *vault.Store, name string) error { return st.Delete(name) }

// EnsurePolicy writes default policy.yaml if absent.
func EnsurePolicy(dir string) error {
	p := filepath.Join(dir, "policy.yaml")
	if _, err := os.Stat(p); os.IsNotExist(err) {
		return os.WriteFile(p, []byte("defaults:\n  unknown_host: tunnel\n  scrub_to_llm: pseudonymize\n  scrub_to_untrusted: mask\n  confidence_threshold: 0.7\naudit:\n  level: events\n  retention: 30d\n"), 0o600)
	}
	return nil
}

// LoadPolicy loads policy.yaml in dir (defaults when absent).
func LoadPolicy(dir string) (policy.Policy, []byte, error) {
	raw, err := os.ReadFile(filepath.Join(dir, "policy.yaml"))
	if os.IsNotExist(err) {
		return policy.Default(), nil, nil
	}
	if err != nil {
		return policy.Policy{}, nil, err
	}
	p := policy.Default()
	if err := yaml.Unmarshal(raw, &p); err != nil {
		return policy.Policy{}, nil, err
	}
	return p, raw, nil
}
