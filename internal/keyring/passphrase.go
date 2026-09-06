// Package keyring — passphrase backend (WP-02).
//
// key.json holds NO secret material: version, kdf params, random salt,
// and an AES-GCM verifier sealing the literal "sentinel-kdf-v1" under the
// derived key. Wrong passphrase ⇒ ErrWrongPassphrase, fail closed.
package keyring

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"sentinel/internal/memguard"

	"golang.org/x/crypto/argon2"
)

const (
	KeyFileName   = "key.json"
	verifierPlain = "sentinel-kdf-v1"
	saltLen       = 32
)

// ErrWrongPassphrase is returned when the verifier check fails.
var ErrWrongPassphrase = errors.New("keyring: wrong passphrase")

// Params are the KDF parameters stored in key.json (rais able later).
type Params struct {
	Version     int    `json:"version"`
	KDF         string `json:"kdf"`
	Salt        string `json:"salt"`
	Time        uint32 `json:"time"`
	MemoryKiB   uint32 `json:"memory_kib"`
	Parallelism uint8  `json:"parallelism"`
	Verifier    string `json:"verifier"`
}

// DefaultParams returns the WP-02 baseline parameters.
// SENTINEL_KDF_MEM_KIB / SENTINEL_KDF_TIME override them (tests only);
// production defaults are t=3, m=256MiB, p=4 per SPEC WP-02.
func DefaultParams() (time uint32, memKiB uint32, par uint8) {
	time, memKiB, par = 3, 262144, 4
	if v := os.Getenv("SENTINEL_KDF_MEM_KIB"); v != "" {
		var n uint32
		if _, err := fmt.Sscanf(v, "%d", &n); err == nil && n >= 8 {
			memKiB = n
		}
	}
	if v := os.Getenv("SENTINEL_KDF_TIME"); v != "" {
		var n uint32
		if _, err := fmt.Sscanf(v, "%d", &n); err == nil && n >= 1 {
			time = n
		}
	}
	return time, memKiB, par
}
func derive(passphrase, salt []byte, time, memKiB uint32, par uint8) []byte {
	return argon2.IDKey(passphrase, salt, time, memKiB*1024, par, 32)
}

func sealVerifier(key []byte) (string, error) {
	blk, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	g, err := cipher.NewGCM(blk)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, g.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}
	ct := g.Seal(nonce, nonce, []byte(verifierPlain), nil)
	return base64.StdEncoding.EncodeToString(ct), nil
}

func checkVerifier(key []byte, enc string) error {
	raw, err := base64.StdEncoding.DecodeString(enc)
	if err != nil {
		return fmt.Errorf("%w: bad verifier encoding", ErrWrongPassphrase)
	}
	blk, err := aes.NewCipher(key)
	if err != nil {
		return err
	}
	g, err := cipher.NewGCM(blk)
	if err != nil {
		return err
	}
	ns := g.NonceSize()
	if len(raw) < ns {
		return fmt.Errorf("%w: verifier mismatch", ErrWrongPassphrase)
	}
	plain, err := g.Open(nil, raw[:ns], raw[ns:], nil)
	if err != nil || string(plain) != verifierPlain {
		return fmt.Errorf("%w: verifier mismatch", ErrWrongPassphrase)
	}
	return nil
}

// KeyFilePath returns the key.json path inside dir.
func KeyFilePath(dir string) string { return filepath.Join(dir, KeyFileName) }

// HasPassphrase reports whether dir holds a key.json.
func HasPassphrase(dir string) bool {
	_, err := os.Stat(KeyFilePath(dir))
	return err == nil
}

// CreatePassphrase derives a fresh key from passphrase with a random salt,
// writes key.json (0600 + ACL narrowing), and returns the derived key.
// Caller MUST zero passphrase and the returned key after use.
func CreatePassphrase(dir string, passphrase []byte) ([]byte, error) {
	if len(passphrase) == 0 {
		return nil, errors.New("keyring: empty passphrase")
	}
	t, m, p := DefaultParams()
	salt := make([]byte, saltLen)
	if _, err := rand.Read(salt); err != nil {
		return nil, err
	}
	key := derive(passphrase, salt, t, m, p)
	ver, err := sealVerifier(key)
	if err != nil {
		memguard.Zero(key)
		return nil, err
	}
	params := Params{
		Version:     1,
		KDF:         "argon2id",
		Salt:        base64.StdEncoding.EncodeToString(salt),
		Time:        t,
		MemoryKiB:   m,
		Parallelism: p,
		Verifier:    ver,
	}
	buf, err := json.Marshal(params)
	if err != nil {
		memguard.Zero(key)
		return nil, err
	}
	path := KeyFilePath(dir)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		memguard.Zero(key)
		return nil, err
	}
	if err := os.WriteFile(path, buf, 0o600); err != nil {
		memguard.Zero(key)
		return nil, err
	}
	if err := narrowFileACL(path); err != nil {
		memguard.Zero(key)
		return nil, err
	}
	out := make([]byte, 32)
	copy(out, key)
	memguard.Zero(key)
	return out, nil
}

// OpenPassphrase derives the key from passphrase using stored params and
// verifies it against the stored verifier before returning.
// Caller MUST zero passphrase and the returned key after use.
func OpenPassphrase(dir string, passphrase []byte) ([]byte, error) {
	buf, err := os.ReadFile(KeyFilePath(dir))
	if err != nil {
		return nil, err
	}
	var params Params
	if err := json.Unmarshal(buf, &params); err != nil {
		return nil, fmt.Errorf("keyring: bad key.json: %w", err)
	}
	if params.Version != 1 || params.KDF != "argon2id" {
		return nil, errors.New("keyring: unsupported key.json version or kdf")
	}
	salt, err := base64.StdEncoding.DecodeString(params.Salt)
	if err != nil || len(salt) != saltLen {
		return nil, errors.New("keyring: bad salt in key.json")
	}
	key := derive(passphrase, salt, params.Time, params.MemoryKiB, params.Parallelism)
	if err := checkVerifier(key, params.Verifier); err != nil {
		memguard.Zero(key)
		return nil, err
	}
	out := make([]byte, 32)
	copy(out, key)
	memguard.Zero(key)
	return out, nil
}
