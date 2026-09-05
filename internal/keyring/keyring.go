package keyring

import (
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"os"
	"path/filepath"

	"github.com/zalando/go-keyring"
	"golang.org/x/crypto/argon2"
)

const service = "sentinel-master"

func dataDir() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".sentinel")
}

// LoadOrCreate returns 32B master key: OS keychain, else Argon2id(passphrase file).
func LoadOrCreate() ([]byte, error) {
	if k, err := keyring.Get(service, "master"); err == nil && len(k) == 64 {
		var key [32]byte
		raw, _ := hex2bin(k)
		copy(key[:], raw)
		return key[:], nil
	}
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return nil, err
	}
	if err := keyring.Set(service, "master", bin2hex(key)); err != nil {
		// fallback: derive from passphrase in file (created by init)
		return deriveFallback()
	}
	return key, nil
}

func deriveFallback() ([]byte, error) {
	p := filepath.Join(dataDir(), "passphrase")
	pw, err := os.ReadFile(p)
	if err != nil {
		return nil, errors.New("no keychain and no ~/.sentinel/passphrase: run sentinel init")
	}
	salt := sha256.Sum256([]byte("sentinel-salt"))
	return argon2.IDKey(pw, salt[:], 1, 64*1024, 4, 32), nil
}

func bin2hex(b []byte) string {
	const h = "0123456789abcdef"
	out := make([]byte, len(b)*2)
	for i, v := range b {
		out[i*2] = h[v>>4]
		out[i*2+1] = h[v&15]
	}
	return string(out)
}

func hex2bin(s string) ([]byte, error) {
	if len(s)%2 != 0 {
		return nil, errors.New("bad hex")
	}
	out := make([]byte, len(s)/2)
	for i := range out {
		var v byte
		for j := range 2 {
			c := s[i*2+j]
			var n byte
			switch {
			case c >= '0' && c <= '9':
				n = c - '0'
			case c >= 'a' && c <= 'f':
				n = c - 'a' + 10
			default:
				return nil, errors.New("bad hex")
			}
			v = v*16 + n
		}
		out[i] = v
	}
	return out, nil
}
