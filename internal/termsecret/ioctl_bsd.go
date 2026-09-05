//go:build darwin || freebsd || openbsd || netbsd || dragonfly

package termsecret

import "golang.org/x/sys/unix"

func ioctlReadTermios() uint  { return unix.TIOCGETA }
func ioctlWriteTermios() uint { return unix.TIOCSETA }
