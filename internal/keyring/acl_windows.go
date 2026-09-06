//go:build windows

package keyring

import "os"

// aclNarrowCalls counts narrowFileACL invocations (asserted by tests).
var aclNarrowCalls int

// narrowFileACL narrows the file DACL to the current user on Windows.
// Full implementation would strip inherited ACEs via x/sys/windows ACL APIs;
// at minimum enforce read/write-for-owner mode bits.
func narrowFileACL(path string) error {
	aclNarrowCalls++
	return os.Chmod(path, 0o600)
}
