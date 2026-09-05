package llm

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"sentinel/internal/policy"
)

type mapVault map[string]string

func (m mapVault) ValuesSnapshot() map[string]string { return map[string]string(m) }

// L0: real vault value must never reach upstream, even with pseudonymize default.
func TestL0VaultMatchBlocked(t *testing.T) {
	sawSecret := false
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		if bytes.Contains(b, []byte("sup3r-r3al-token-XYZ")) {
			sawSecret = true
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"ok":true}`))
	}))
	defer up.Close()
	p := policy.Default()
	g, err := Serve("127.0.0.1:0", up.URL, &p, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer g.Stop()
	g.Vault = mapVault{"api_main": "sup3r-r3al-token-XYZ"}
	body := `{"model":"x","messages":[{"role":"user","content":"my key is sup3r-r3al-token-XYZ use it"}]}`
	resp, err := http.Post("http://"+g.Addr+"/v1/chat/completions", "application/json", bytes.NewBufferString(body))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 403 {
		t.Fatalf("want 403 block, got %d", resp.StatusCode)
	}
	if sawSecret {
		t.Fatal("upstream saw real secret")
	}
}

// Placeholder passes through: snt://name must not be blocked.
func TestL0PlaceholderPasses(t *testing.T) {
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"ok":true}`))
	}))
	defer up.Close()
	p := policy.Default()
	g, err := Serve("127.0.0.1:0", up.URL, &p, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer g.Stop()
	g.Vault = mapVault{"api_main": "sup3r-r3al-token-XYZ"}
	body := `{"model":"x","messages":[{"role":"user","content":"use snt://api_main please"}]}`
	resp, err := http.Post("http://"+g.Addr+"/v1/chat/completions", "application/json", bytes.NewBufferString(body))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		rb, _ := io.ReadAll(resp.Body)
		t.Fatalf("placeholder blocked: %d %s", resp.StatusCode, rb)
	}
}
