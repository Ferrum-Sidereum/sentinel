package mcp

import (
	"testing"
	"time"

	"sentinel/internal/policy"
	"sentinel/internal/scrubber"
)

func TestCheckCallDeny(t *testing.T) {
	deny := map[string]bool{"delete_repository": true}
	line := `{"method":"tools/call","params":{"name":"delete_repository","arguments":{}}}`
	if bad := checkCall(line, deny); bad == "" {
		t.Fatal("deny not triggered")
	}
}

func TestCheckCallForeignPlaceholder(t *testing.T) {
	line := `{"method":"tools/call","params":{"name":"read","arguments":{"token":"snt://other_sec"}}}`
	if bad := checkCall(line, nil); bad == "" {
		t.Fatal("foreign placeholder not blocked")
	}
}

func TestScrubLine(t *testing.T) {
	sess := scrubber.NewSession(time.Hour)
	p := policy.Default()
	thr := p.Defaults.ConfidenceThreshold
	line := `{"result":{"content":[{"text":"mail ivan@x.ru"}]}}`
	out := scrubLine(line, nil, nil, "pseudonymize", sess, thr, func(string, map[string]any) {})
	if out == line || containsStr(out, "ivan@x.ru") {
		t.Fatalf("not scrubbed: %s", out)
	}
}

func containsStr(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
