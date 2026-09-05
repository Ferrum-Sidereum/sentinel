package metrics

import (
	"fmt"
	"net/http"
	"sort"
	"sync"
	"sync/atomic"
	"time"
)

type Metrics struct {
	findings    sync.Map // type -> *atomic.Int64
	latN        atomic.Int64
	latSumNanos atomic.Int64
	latBuckets  sync.Map // le string -> *atomic.Int64
}

var bounds = []float64{0.001, 0.005, 0.01, 0.05, 0.1, 0.5, 1, 5}

func New() *Metrics { return &Metrics{} }

func (m *Metrics) AddFinding(typ string, n int) {
	v, _ := m.findings.LoadOrStore(typ, &atomic.Int64{})
	v.(*atomic.Int64).Add(int64(n))
}

func (m *Metrics) ObserveLatency(d time.Duration) {
	m.latN.Add(1)
	m.latSumNanos.Add(d.Nanoseconds())
	s := d.Seconds()
	for _, b := range bounds {
		if s <= b {
			k := fmt.Sprintf("%g", b)
			v, _ := m.latBuckets.LoadOrStore(k, &atomic.Int64{})
			v.(*atomic.Int64).Add(1)
		}
	}
}

func (m *Metrics) Handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; version=0.0.4")
		var types []string
		m.findings.Range(func(k, v any) bool { types = append(types, k.(string)); return true })
		sort.Strings(types)
		for _, t := range types {
			v, _ := m.findings.Load(t)
			fmt.Fprintf(w, "sentinel_findings_total{type=%q} %d\n", t, v.(*atomic.Int64).Load())
		}
		n := m.latN.Load()
		fmt.Fprintf(w, "sentinel_scrub_latency_count %d\n", n)
		fmt.Fprintf(w, "sentinel_scrub_latency_sum %f\n", float64(m.latSumNanos.Load())/1e9)
		for _, b := range bounds {
			k := fmt.Sprintf("%g", b)
			var c int64
			if v, ok := m.latBuckets.Load(k); ok {
				c = v.(*atomic.Int64).Load()
			}
			fmt.Fprintf(w, "sentinel_scrub_latency_bucket{le=%q} %d\n", k, c)
		}
		fmt.Fprintf(w, "sentinel_scrub_latency_bucket{le=\"+Inf\"} %d\n", n)
	})
}
