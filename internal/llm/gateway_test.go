package llm

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"sentinel/internal/policy"
)

func TestGatewayPseudoRehydrate(t *testing.T) {
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		var m struct {
			Messages []struct{ Content string `json:"content"` } `json:"messages"`
		}
		json.Unmarshal(b, &m)
		got := m.Messages[0].Content
		if got == "" || contains(got, "ivan@x.ru") {
			t.Errorf("upstream saw raw PII: %q", got)
		}
		// echo back with alias (upstream parrots what it got)
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"reply":` + strconv(got) + `}`))
	}))
	defer up.Close()
	p := policy.Default()
	g, err := Serve("127.0.0.1:0", up.URL, &p, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer g.Stop()
	body := `{"model":"x","messages":[{"role":"user","content":"mail ivan@x.ru"}]}`
	resp, err := http.Post("http://"+g.Addr+"/v1/chat/completions", "application/json", bytes.NewBufferString(body))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	rb, _ := io.ReadAll(resp.Body)
	if !contains(string(rb), "ivan@x.ru") {
		t.Fatalf("no rehydrate: %s", rb)
	}
}

func contains(s, sub string) bool { return bytes.Contains([]byte(s), []byte(sub)) }

func strconv(s string) string {
	b, _ := json.Marshal(s)
	return string(b)
}
