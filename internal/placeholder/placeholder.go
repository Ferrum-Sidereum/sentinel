package placeholder

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"regexp"
)

var (
	canonicalRe = regexp.MustCompile(`\bsnt://([A-Za-z0-9][A-Za-z0-9_.-]{0,127})(?:@(\d+))?\b`)
	safeRe      = regexp.MustCompile(`\bSNT_PH_([A-Z0-9_]{1,64})_([0-9a-f]{8})\b`)
	valueRe     = regexp.MustCompile(`\bsnt://[A-Za-z0-9][A-Za-z0-9_.-]{0,127}(?:@\d+)?\b|\bSNT_PH_[A-Z0-9_]{1,64}_[0-9a-f]{8}\b`)
)

// Checksum: first 8 hex of sha256("sentinel:"+name).
func Checksum(name string) string {
	h := sha256.Sum256([]byte("sentinel:" + name))
	return hex.EncodeToString(h[:])[:8]
}

// Canonical returns snt://name.
func Canonical(name string) string { return "snt://" + name }

// Safe returns SNT_PH_NAME_checksum.
func Safe(name string) string {
	safe := ""
	for _, r := range name {
		switch {
		case r >= 'a' && r <= 'z':
			safe += string(r - 'a' + 'A')
		case r >= 'A' && r <= 'Z' || r >= '0' && r <= '9':
			safe += string(r)
		default:
			safe += "_"
		}
	}
	return fmt.Sprintf("SNT_PH_%s_%s", safe, Checksum(name))
}

// Find returns all placeholder strings in text.
func Find(text string) []string { return valueRe.FindAllString(text, -1) }

// ValidCanonical reports whether ph is a well-formed canonical placeholder
// for a known name (checksum n/a for canonical form; name match checked by caller).
func ValidCanonical(ph string) bool { return canonicalRe.MatchString(ph) }

// ValidSafe verifies checksum suffix against embedded name (best effort).
func ValidSafe(ph, name string) bool {
	m := safeRe.FindStringSubmatch(ph)
	if m == nil {
		return false
	}
	return m[2] == Checksum(name)
}
