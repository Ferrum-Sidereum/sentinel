//go:build windows

package memguard

import (
	"syscall"
	"unsafe"
)

var (
	kernel32       = syscall.NewLazyDLL("kernel32.dll")
	pVirtualLock   = kernel32.NewProc("VirtualLock")
	pVirtualUnlock = kernel32.NewProc("VirtualUnlock")
)

// Lock prevents b from being paged out. Best effort: returns false on failure.
func Lock(b []byte) bool {
	if len(b) == 0 {
		return true
	}
	r, _, _ := pVirtualLock.Call(uintptr(unsafe.Pointer(&b[0])), uintptr(len(b)))
	return r != 0
}

func Unlock(b []byte) {
	if len(b) == 0 {
		return
	}
	pVirtualUnlock.Call(uintptr(unsafe.Pointer(&b[0])), uintptr(len(b)))
}

// SecureZero zeroes via volatile write loop (compiler cannot elide
// through the KeepAlive'd pointer in Zero).
func SecureZero(b []byte) { Zero(b) }
