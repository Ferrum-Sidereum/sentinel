// Package termsecret reads secret values from the terminal without echo.
//
// Read uses no-echo console input when stdin is a TTY and a plain read
// when stdin is a pipe. Exactly one trailing newline (LF or CRLF) is
// stripped; no other whitespace is touched. The caller owns the returned
// buffer and must zero it after use (see internal/memguard.Zero).
package termsecret

import (
	"errors"
	"io"
	"os"
)

// ErrEmpty is returned when the input carries no secret bytes.
var ErrEmpty = errors.New("termsecret: empty value")

// Read prompts on stderr (TTY only) and reads a secret from stdin.
func Read(prompt string) ([]byte, error) {
	if IsTTY(os.Stdin) {
		return readNoEcho(os.Stdin, prompt)
	}
	return readPipe(os.Stdin)
}

// IsTTY reports whether f is a character device.
func IsTTY(f *os.File) bool {
	fi, err := f.Stat()
	if err != nil {
		return false
	}
	return fi.Mode()&os.ModeCharDevice != 0
}

// readPipe reads all of r and strips exactly one trailing newline.
func readPipe(r io.Reader) ([]byte, error) {
	b, err := io.ReadAll(r)
	if err != nil {
		return nil, err
	}
	b = stripOneNewline(b)
	if len(b) == 0 {
		return nil, ErrEmpty
	}
	return b, nil
}

// stripOneNewline removes a single trailing "\n" or "\r\n".
func stripOneNewline(b []byte) []byte {
	if len(b) > 0 && b[len(b)-1] == '\n' {
		b = b[:len(b)-1]
		if len(b) > 0 && b[len(b)-1] == '\r' {
			b = b[:len(b)-1]
		}
	}
	return b
}
