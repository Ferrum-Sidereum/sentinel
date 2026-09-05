//go:build windows

package termsecret

import (
	"fmt"
	"os"
	"unsafe"

	"golang.org/x/sys/windows"
)

var kernel32 = windows.NewLazySystemDLL("kernel32.dll")
var procReadConsoleW = kernel32.NewProc("ReadConsoleW")

// readNoEcho reads one line from a Windows console without echo.
func readNoEcho(f *os.File, prompt string) ([]byte, error) {
	h := windows.Handle(f.Fd())
	var mode uint32
	if err := windows.GetConsoleMode(h, &mode); err != nil {
		return readPipe(f)
	}
	noEcho := mode &^ (windows.ENABLE_ECHO_INPUT | windows.ENABLE_LINE_INPUT)
	if err := windows.SetConsoleMode(h, noEcho); err != nil {
		return nil, err
	}
	defer windows.SetConsoleMode(h, mode)

	if prompt != "" {
		fmt.Fprint(os.Stderr, prompt)
	}

	buf := make([]uint16, 4096)
	// ReadConsoleW with a small buffer; loop until newline.
	out := make([]byte, 0, 256)
	for {
		var got uint32
		r1, _, _ := procReadConsoleW.Call(
			uintptr(h),
			uintptr(unsafe.Pointer(&buf[0])),
			uintptr(uint32(len(buf))),
			uintptr(unsafe.Pointer(&got)),
			0,
		)
		if r1 == 0 {
			return nil, ErrEmpty
		}
		for _, c := range buf[:got] {
			if c == '\n' {
				goto done
			}
			if c != '\r' {
				out = append(out, string(rune(c))...)
			}
		}
	}
done:
	fmt.Fprint(os.Stderr, "\n")
	if len(out) == 0 {
		return nil, ErrEmpty
	}
	return out, nil
}
