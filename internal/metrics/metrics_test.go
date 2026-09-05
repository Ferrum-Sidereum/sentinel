package metrics

import (
	"io"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestHandler(t *testing.T) {
	m := New()
	m.AddFinding("EMAIL", 2)
	m.AddFinding("PHONE_RU", 1)
	m.ObserveLatency(5 * time.Millisecond)
	r := httptest.NewRequest("GET", "/metrics", nil)
	w := httptest.NewRecorder()
	m.Handler().ServeHTTP(w, r)
	b, _ := io.ReadAll(w.Result().Body)
	s := string(b)
	for _, want := range []string{
		`sentinel_findings_total{type="EMAIL"} 2`,
		`sentinel_findings_total{type="PHONE_RU"} 1`,
		"sentinel_scrub_latency_count 1",
	} {
		if !strings.Contains(s, want) {
			t.Errorf("missing %q in:\n%s", want, s)
		}
	}
}
