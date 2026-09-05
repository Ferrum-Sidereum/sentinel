package memguard

import (
	"runtime"
	"unsafe"
)

// Zero overwrites b. Callers MUST invoke it via defer right after use.
func Zero(b []byte) {
	for i := range b {
		b[i] = 0
	}
	runtime.KeepAlive(unsafe.Pointer(&b))
}

// ZeroString copies s to a mutable buffer, calls fn, then zeroes the buffer.
func ZeroString(s string, fn func(b []byte)) {
	b := []byte(s)
	defer Zero(b)
	fn(b)
}
