//go:build !windows

package keyring

import "os"

// narrowFileACL enforces 0600 on Unix.
func narrowFileACL(path string) error { return os.Chmod(path, 0o600) }
