package main

import (
	"io"
	"os"
	"strings"
	"testing"
)

func TestVersionPrintsStampedFields(t *testing.T) {
	old := version
	version, commit, date = "v1.2.3", "abc123", "2026-01-01"
	defer func() { version = old }()

	r, w, _ := os.Pipe()
	stdout := os.Stdout
	os.Stdout = w
	cmdVersion()
	w.Close()
	os.Stdout = stdout
	out, _ := io.ReadAll(r)

	if !strings.Contains(string(out), "sentinel v1.2.3") {
		t.Fatalf("version output missing tag: %q", out)
	}
	if !strings.Contains(string(out), "abc123") {
		t.Fatalf("version output missing commit: %q", out)
	}
}
