package llm

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"sentinel/internal/policy"
)

func TestEmbeddingsBlocked(t *testing.T) {
	p := policy.Default()
	g, err := Serve("127.0.0.1:0", "http://127.0.0.1:1", &p, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer g.Stop()
	resp, err := http.Post("http://"+g.Addr+"/v1/embeddings", "application/json",
		bytes.NewBufferString(`{"model":"x","input":"hi"}`))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 403 {
		t.Fatalf("want 403, got %d", resp.StatusCode)
	}
}

func TestStreamingRehydrate(t *testing.T) {
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		// find alias the gateway created
		w.Header().Set("Content-Type", "text/event-stream")
		// echo: parse content out crudely — just return a chunk; real alias tested via non-stream path
		_ = b
		w.Write([]byte("data: {\"delta\":\"hello world\"}\n\ndata: [DONE]\n\n"))
	}))
	defer up.Close()
	p := policy.Default()
	g, err := Serve("127.0.0.1:0", up.URL, &p, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer g.Stop()
	body := `{"model":"x","stream":true,"messages":[{"role":"user","content":"mail ivan@x.ru"}]}`
	resp, err := http.Post("http://"+g.Addr+"/v1/chat/completions", "application/json", bytes.NewBufferString(body))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if ct := resp.Header.Get("Content-Type"); ct != "text/event-stream" {
		t.Fatalf("want SSE, got %q", ct)
	}
	rb, _ := io.ReadAll(resp.Body)
	if !contains(string(rb), "hello world") {
		t.Fatalf("no SSE body: %s", rb)
	}
}

func TestStreamingSplitAlias(t *testing.T) {
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		_ = b
		w.Header().Set("Content-Type", "text/event-stream")
		fl, _ := w.(http.Flusher)
		// split <EMAIL_1> across 3 chunks/lines
		for _, c := range []string{"data: hi <EM\n\n", "data: AIL\n\n", "data: _1> there\n\n", "data: [DONE]\n\n"} {
			w.Write([]byte(c))
			if fl != nil {
				fl.Flush()
			}
		}
	}))
	defer up.Close()
	p := policy.Default()
	g, err := Serve("127.0.0.1:0", up.URL, &p, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer g.Stop()
	// seed session mapping directly
	alias := g.Sess.Alias("EMAIL", "ivan@x.ru")
	if alias == "" {
		t.Fatal("no alias")
	}
	body := `{"model":"x","stream":true,"messages":[{"role":"user","content":"hi"}]}`
	resp, err := http.Post("http://"+g.Addr+"/v1/chat/completions", "application/json", bytes.NewBufferString(body))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	rb, _ := io.ReadAll(resp.Body)
	if !contains(string(rb), "ivan@x.ru") {
		t.Fatalf("split alias not rehydrated: %q", rb)
	}
	if contains(string(rb), alias) {
		t.Fatalf("alias leaked: %q", rb)
	}
}
