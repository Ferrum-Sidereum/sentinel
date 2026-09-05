//go:build !windows

package main

import "os"

// For backend tests only; the desktop target is Windows.
func replaceFile(from, to string) error { return os.Rename(from, to) }
