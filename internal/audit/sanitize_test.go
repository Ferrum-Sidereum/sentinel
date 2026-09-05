package audit

import (
	"strings"
	"testing"
)

// §14: audit log must never contain secret values / PII.
func TestAuditNoLeak(t *testing.T) {
	secrets := []string{
		"sk-proj-abcdefghijklmnop123456",
		"ghp_abcdefghijklmnopqrstuvwx",
		"4111111111111111",
		"ivan@test.ru",
		"MyS3cretP@ssw0rd!",
	}
	for _, s := range secrets {
		line := MarshalEvent("sess", "test", map[string]any{
			"value": s, "secret": s, "content": s, "note": "ctx " + s,
		})
		if strings.Contains(line, s) {
			t.Errorf("audit leak: %s", line)
		}
		if strings.Contains(line, "ivan@test.ru") {
			t.Errorf("audit PII leak: %s", line)
		}
	}
	// non-secret short text passes through
	line := MarshalEvent("s", "t", map[string]any{"note": "ok"})
	if !strings.Contains(line, "ok") {
		t.Errorf("over-redaction: %s", line)
	}
}
