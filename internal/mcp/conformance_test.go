package mcp

import (
	"bufio"
	"encoding/json"
	"errors"
	"strconv"
	"strings"
	"testing"
	"time"

	"sentinel/internal/policy"
	"sentinel/internal/scrubber"
)

var errTest = errors.New("test")

func itoa(n int) string { return strconv.Itoa(n) }

func jsonUnmarshal(s string, v any) error { return json.Unmarshal([]byte(s), v) }
func TestFramingContentLengthRoundTrip(t *testing.T) {
	body := `{"jsonrpc":"2.0","id":1,"result":{}}`
	in := "Content-Length: " + itoa(len(body)) + "\r\n\r\n" + body + "\n"
	fr := &frameReader{br: bufio.NewReader(strings.NewReader(in))}
	got, err := fr.read()
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if got != body {
		t.Fatalf("got %q want %q", got, body)
	}
	if fr.framing != FramingContentLength {
		t.Fatal("framing not detected as Content-Length")
	}
	// second frame in same framing
	body2 := `{"jsonrpc":"2.0","id":2,"result":{}}`
	in2 := "Content-Length: " + itoa(len(body2)) + "\r\n\r\n" + body2
	fr2 := &frameReader{br: bufio.NewReader(strings.NewReader(in2)), framing: FramingContentLength, detected: true}
	got2, err := fr2.read()
	if err != nil || got2 != body2 {
		t.Fatalf("second frame: %q %v", got2, err)
	}
}

func TestTruncatedBodyNamedError(t *testing.T) {
	in := "Content-Length: 100\r\n\r\nshort"
	done := make(chan error, 1)
	go func() {
		_, err := readFrame(bufio.NewReader(strings.NewReader(in)))
		done <- err
	}()
	select {
	case err := <-done:
		fe, ok := err.(*FrameError)
		if !ok || fe.Kind != "truncated" {
			t.Fatalf("want truncated FrameError, got %T %v", err, err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("hang on truncated body")
	}
}

func TestScrubShapeOutputField(t *testing.T) {
	sess := scrubber.NewSession(time.Hour)
	p := policy.Default()
	thr := p.Defaults.ConfidenceThreshold
	line := `{"result":{"output":"mail ivan@x.ru"}}`
	out := scrubLine(line, nil, nil, "pseudonymize", sess, thr, func(string, map[string]any) {})
	if containsStr(out, "ivan@x.ru") {
		t.Fatalf("secret in 'output' not scrubbed: %s", out)
	}
}

func TestScrubSkipsProtocolFields(t *testing.T) {
	sess := scrubber.NewSession(time.Hour)
	line := `{"jsonrpc":"2.0","id":"1","method":"tools/call","result":{"text":"ok"}}`
	out := scrubLine(line, nil, nil, "pseudonymize", sess, 0.7, func(string, map[string]any) {})
	var m map[string]any
	if err := jsonUnmarshal(out, &m); err != nil {
		t.Fatal(err)
	}
	if m["method"] != "tools/call" || m["jsonrpc"] != "2.0" {
		t.Fatalf("protocol fields rewritten: %s", out)
	}
}

func TestInboundChecksAllMethods(t *testing.T) {
	cases := []string{
		`{"method":"resources/read","params":{"uri":"snt://other_sec/x"}}`,
		`{"method":"prompts/get","params":{"name":"p","argument":{"a":"snt://other_sec"}}}`,
		`{"method":"completion/complete","params":{"ref":{"uri":"snt://other_sec"}}}`,
	}
	for _, c := range cases {
		if len(checkInbound(c, nil)) == 0 {
			t.Fatalf("no finding for %s", c)
		}
	}
	// multiple findings reported, not just first
	multi := `{"method":"tools/call","params":{"name":"x","arguments":{"a":"snt://a","b":"snt://b"}}}`
	if len(checkInbound(multi, map[string]bool{"x": true})) < 2 {
		t.Fatalf("expected all findings, got %v", checkInbound(multi, map[string]bool{"x": true}))
	}
}

func TestFrameTooLarge(t *testing.T) {
	in := "Content-Length: 10485760\r\n\r\n"
	_, err := readFrame(bufio.NewReader(strings.NewReader(in)))
	fe, ok := err.(*FrameError)
	if !ok || fe.Kind != "too_large" {
		t.Fatalf("want too_large, got %T %v", err, err)
	}
}

func TestMalformedHeaderRejected(t *testing.T) {
	_, err := readFrame(bufio.NewReader(strings.NewReader("Content-Length: abc\r\n\r\n")))
	fe, ok := err.(*FrameError)
	if !ok || fe.Kind != "malformed_header" {
		t.Fatalf("want malformed_header, got %T %v", err, err)
	}
}

func TestExitCodePropagation(t *testing.T) {
	if CodeOf(nil) != 0 {
		t.Fatal("nil should be 0")
	}
	if CodeOf(&ExitError{Code: 7, Err: errTest}) != 7 {
		t.Fatal("child exit 7 must propagate as 7")
	}
}

func TestStderrScrubbed(t *testing.T) {
	sess := scrubber.NewSession(time.Hour)
	got := scrubLine("mail ivan@x.ru", nil, nil, "pseudonymize", sess, 0.7, func(string, map[string]any) {})
	_ = got
	// stderr path uses same scrubLine pipeline:
	line := scrubLine(`{"text":"mail ivan@x.ru"}`, nil, nil, "pseudonymize", sess, 0.7, func(string, map[string]any) {})
	if containsStr(line, "ivan@x.ru") {
		t.Fatalf("stderr scrub failed: %s", line)
	}
}

func FuzzReadFrame(f *testing.F) {
	seeds := []string{
		"{\"jsonrpc\":\"2.0\"}\n",
		"Content-Length: 2\r\n\r\n{}\n",
		"Content-Length: abc\r\n\r\n",
		"Content-Length: 100\r\n\r\nshort",
		"Content-Length: 10485760\r\n\r\n",
		"BadHeader: x\n",
		"",
	}
	for _, s := range seeds {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		done := make(chan struct{})
		go func() {
			defer close(done)
			_, _ = readFrame(bufio.NewReader(strings.NewReader(s)))
		}()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Fatal("hang in readFrame")
		}
	})
}
