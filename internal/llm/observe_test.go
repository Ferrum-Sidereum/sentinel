package llm

import (
	"io"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"sentinel/internal/scrubber"
)

func TestMetricsAndUI(t *testing.T) {
	g := &Gateway{Sess: scrubber.NewSession(time.Hour)}
	for _, path := range []string{"/metrics", "/ui"} {
		r := httptest.NewRequest("GET", path, nil)
		w := httptest.NewRecorder()
		g.ServeHTTP(w, r)
		b, _ := io.ReadAll(w.Result().Body)
		if w.Code != 200 || len(b) == 0 {
			t.Errorf("%s: code=%d len=%d", path, w.Code, len(b))
		}
		if path == "/metrics" && !strings.Contains(string(b), "sentinel_scrub_latency_count") {
			t.Errorf("metrics missing counter")
		}
	}
}
