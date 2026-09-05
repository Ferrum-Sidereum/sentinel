//go:build unix

package memguard

import "golang.org/x/sys/unix"

// Lock prevents b from being paged out. Best effort: returns false on failure.
func Lock(b []byte) bool {
	if len(b) == 0 {
		return true
	}
	return unix.Mlock(b) == nil
}

func Unlock(b []byte) {
	if len(b) == 0 {
		return
	}
	_ = unix.Munlock(b)
}

// SecureZero zeroes b; runtime.KeepAlive in Zero prevents elision.
func SecureZero(b []byte) { Zero(b) }
