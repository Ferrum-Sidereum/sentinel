package mcp

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"time"

	"sentinel/internal/audit"
	"sentinel/internal/broker"
	"sentinel/internal/vault"
)

// BrokerEnv is the loopback endpoint child uses to resolve snt:// per call.
const BrokerEnv = "SENTINEL_BROKER_URL"

// ServeBroker starts a loopback HTTP endpoint applying the broker gate per
// call. Only loopback; returns base URL and stop func.
func ServeBroker(br broker.Broker, st *vault.Store, l *audit.Logger, consumer string) (string, func(), error) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return "", nil, err
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/resolve", func(w http.ResponseWriter, r *http.Request) {
		var q struct {
			Secret string `json:"secret"`
			Dest   string `json:"dest"`
		}
		if err := json.NewDecoder(r.Body).Decode(&q); err != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		val, dec, err := broker.Resolve(r.Context(), br, vaultStore{st}, broker.Request{
			Secret: q.Secret, Consumer: consumer, Dest: q.Dest,
			Reason: "broker mode", Requested: time.Now(),
		})
		if l != nil {
			l.Log("", "broker_resolve", map[string]any{"secret": q.Secret, "child": consumer, "dests": []string{q.Dest}, "decision": dec.Allow, "rule": dec.Rule})
		}
		if err != nil || val == nil {
			http.Error(w, "denied", http.StatusForbidden)
			return
		}
		defer zero(val)
		w.Header().Set("Content-Type", "application/octet-stream")
		_, _ = w.Write(val)
	})
	srv := &http.Server{Handler: mux}
	go func() { _ = srv.Serve(ln) }()
	stop := func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = srv.Shutdown(ctx)
	}
	return "http://" + ln.Addr().String(), stop, nil
}

// brokerEnvFor builds child env for broker mode: placeholders stay, endpoint set.
func brokerEnvFor(env []string, br broker.Broker, st *vault.Store, l *audit.Logger, consumer string) ([]string, func(), error) {
	url, stop, err := ServeBroker(br, st, l, consumer)
	if err != nil {
		return nil, nil, err
	}
	out := append(append([]string{}, env...), BrokerEnv+"="+url)
	return out, stop, nil
}
