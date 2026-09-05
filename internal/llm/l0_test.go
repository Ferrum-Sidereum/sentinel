package llm

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"sentinel/internal/policy"
	"sentinel/internal/scrubber"
)

type mapVault map[string]string

func (m mapVault) NewMatcher() (scrubber.VaultMatcher, error) { return testMapMatcher(m), nil }

type testMapMatcher map[string]string

func (m testMapMatcher) FindAll(text string) []scrubber.Match {
	var out []scrubber.Match
	for name, val := range m {
		for i := 0; i+len(val) <= len(text); {
			j := indexOf(text[i:], val)
			if j < 0 {
				break
			}
			s := i + j
			out = append(out, scrubber.Match{Name: name, Start: s, End: s + len(val)})
			i = s + len(val)
		}
	}
	return out
}

func (m testMapMatcher) Close() {}

func indexOf(hay, needle string) int {
	for i := 0; i+len(needle) <= len(hay); i++ {
		if hay[i:i+len(needle)] == needle {
			return i
		}
	}
	return -1
}

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
