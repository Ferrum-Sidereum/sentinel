package scrubber

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

type goldenCase struct {
	Input       string   `json:"input"`
	ExpectTypes []string `json:"expect_types"`
}

func loadGolden(t *testing.T) []goldenCase {
	t.Helper()
	_, f, _, _ := runtime.Caller(0)
	root := filepath.Join(filepath.Dir(f), "..", "..", "testdata", "golden", "basic.json")
	b, err := os.ReadFile(root)
	if err != nil {
		t.Skip("no golden corpus")
	}
	var cs []goldenCase
	if err := json.Unmarshal(b, &cs); err != nil {
		t.Fatal(err)
	}
	return cs
}

// precision/recall gate: every expected type must be found; no false positives on clean inputs.
func TestGoldenCorpus(t *testing.T) {
	for i, c := range loadGolden(t) {
		f := Scan(c.Input, nil, nil)
		got := map[string]bool{}
		for _, x := range f {
			got[x.Type] = true
		}
		for _, want := range c.ExpectTypes {
			if !got[want] {
				t.Errorf("case %d %q: missing %s (got %v)", i, c.Input, want, f)
			}
		}
		if len(c.ExpectTypes) == 0 && len(f) != 0 {
			t.Errorf("case %d %q: false positive %v", i, c.Input, f)
		}
	}
}
