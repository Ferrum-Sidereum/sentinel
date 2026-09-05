package llm

import (
	"html"
	"net/http"
	"strings"
	"sync"
	"time"

	"sentinel/internal/metrics"
)

// Metrics is the gateway-wide Prometheus registry.
var Metrics = metrics.New()

var mu sync.RWMutex

// UIHandler renders a minimal event feed (/ui).
func UIHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		var sb strings.Builder
		sb.WriteString("<!doctype html><html><head><meta charset=utf-8><title>sentinel llm events</title></head><body><h1>sentinel llm gateway</h1><p>See <a href=\"/metrics\">/metrics</a>.</p><ul>")
		for _, e := range recentEvents(100) {
			if len(e) > 300 {
				e = e[:300] + "…"
			}
			sb.WriteString("<li>" + html.EscapeString(e) + "</li>")
		}
		sb.WriteString("</ul></body></html>")
		w.Write([]byte(sb.String()))
	})
}

var eventRing = make([]string, 0, 512)

func recentEvents(n int) []string {
	mu.RLock()
	defer mu.RUnlock()
	if len(eventRing) <= n {
		out := make([]string, len(eventRing))
		copy(out, eventRing)
		return out
	}
	return append([]string(nil), eventRing[len(eventRing)-n:]...)
}

func recordEvent(s string) {
	mu.Lock()
	defer mu.Unlock()
	eventRing = append(eventRing, time.Now().UTC().Format(time.RFC3339)+" "+s)
	if len(eventRing) > 512 {
		eventRing = eventRing[len(eventRing)-512:]
	}
}
