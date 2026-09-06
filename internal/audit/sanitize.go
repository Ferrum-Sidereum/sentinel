package audit

import (
	"encoding/json"
	"fmt"
	"strings"
)

// secretKeys are field names whose values MUST never reach the log.
var secretKeys = map[string]bool{
	"value": true, "secret": true, "password": true, "token": true,
	"api_key": true, "apikey": true, "passwd": true, "pwd": true,
	"authorization": true, "body": true, "content": true, "prompt": true,
}

const maxFieldLen = 256

// Sanitize replaces secret values with [REDACTED] and truncates long strings.
// Numbers that look like card material (13+ digits) are also redacted.
func Sanitize(fields map[string]any) map[string]any {
	if fields == nil {
		return nil
	}
	out := make(map[string]any, len(fields))
	for k, v := range fields {
		if secretKeys[strings.ToLower(k)] {
			out[k] = "[REDACTED]"
			continue
		}
		out[k] = scrubVal(v)
	}
	return out
}

func scrubVal(v any) any {
	switch t := v.(type) {
	case string:
		if len(t) > maxFieldLen {
			t = t[:maxFieldLen] + "…[TRUNC]"
		}
		if looksSecret(t) {
			return "[REDACTED]"
		}
		return t
	case []byte:
		return "[REDACTED]"
	case map[string]any:
		return Sanitize(t)
	default:
		s := fmt.Sprint(v)
		if looksSecret(s) && len(s) > 12 {
			return "[REDACTED]"
		}
		return v
	}
}

// looksSecret: long digit runs (cards), emails, or sk-/ghp_-style prefixes
// anywhere inside the string (secrets may be embedded in a longer note).
func looksSecret(s string) bool {
	if strings.Contains(s, "sk-") || strings.Contains(s, "ghp_") ||
		strings.Contains(s, "xoxb-") || strings.Contains(s, "AKIA") ||
		strings.Contains(s, "@") {
		return true
	}
	digits := 0
	for _, r := range s {
		if r >= '0' && r <= '9' {
			digits++
			if digits >= 13 {
				return true
			}
		} else {
			digits = 0
		}
	}
	return false
}

// MarshalEvent renders a log line with sanitized fields (for tests/CI).
func MarshalEvent(session, typ string, fields map[string]any) string {
	e := Record{Type: typ, Session: session, Fields: Sanitize(fields)}
	b, _ := json.Marshal(e)
	return string(b)
}
