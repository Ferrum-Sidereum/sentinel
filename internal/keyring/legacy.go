package keyring

import (
	"crypto/sha256"

	"golang.org/x/crypto/argon2"
)

// DeriveLegacy reproduces the pre-WP-02 fallback KDF for migration only:
// argon2id over the raw legacy file bytes with fixed global salt
// sha256("sentinel-salt"), t=1, m=64MiB, p=4. NEVER use for new keys.
func DeriveLegacy(raw []byte) []byte {
	salt := sha256.Sum256([]byte("sentinel-salt"))
	return argon2.IDKey(raw, salt[:], 1, 64*1024, 4, 32)
}
