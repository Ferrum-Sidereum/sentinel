//go:build !windows

package termsecret

import (
	"fmt"
	"os"

	"golang.org/x/sys/unix"
)

// readNoEcho reads one line from a POSIX TTY with echo disabled.
func readNoEcho(f *os.File, prompt string) ([]byte, error) {
	fd := int(f.Fd())
	termios, err := unix.IoctlGetTermios(fd, ioctlReadTermios())
	if err != nil {
		return readPipe(f)
	}
	raw := *termios
	raw.Lflag &^= unix.ECHO | unix.ECHONL | unix.ICANON
	if err := unix.IoctlSetTermios(fd, ioctlWriteTermios(), &raw); err != nil {
		return nil, err
	}
	defer unix.IoctlSetTermios(fd, ioctlWriteTermios(), termios)

	if prompt != "" {
		fmt.Fprint(os.Stderr, prompt)
	}

	out := make([]byte, 0, 256)
	one := make([]byte, 1)
	for {
		n, err := unix.Read(fd, one)
		if err != nil || n == 0 {
			break
		}
		if one[0] == '\n' {
			break
		}
		out = append(out, one[0])
	}
	fmt.Fprint(os.Stderr, "\n")
	out = stripOneNewline(out)
	if len(out) == 0 {
		return nil, ErrEmpty
	}
	return out, nil
}
