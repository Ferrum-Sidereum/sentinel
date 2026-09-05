package memguard

import "testing"

func TestZero(t *testing.T) {
	b := []byte("supersecret-data-123")
	Zero(b)
	for _, c := range b {
		if c != 0 {
			t.Fatal("not zeroed")
		}
	}
}

func TestLockUnlock(t *testing.T) {
	b := []byte("x-secret-value")
	if !Lock(b) {
		t.Skip("mlock unavailable (privilege/limit)")
	}
	defer Unlock(b)
	SecureZero(b)
	if string(b) != string(make([]byte, len(b))) {
		t.Fatal("not zeroed")
	}
}
