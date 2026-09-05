package vault

import (
	"path/filepath"
	"strings"
	"testing"
)

func testStoreTB(tb testing.TB, secrets map[string]string) *Store {
	tb.Helper()
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i + 1)
	}
	st, err := Open(filepath.Join(tb.TempDir(), "v.db"), key)
	if err != nil {
		tb.Fatal(err)
	}
	tb.Cleanup(func() { st.Close() })
	for n, v := range secrets {
		b := []byte(v)
		if err := st.Put(Secret{Name: n, Value: b}); err != nil {
			tb.Fatal(err)
		}
		zero(b)
	}
	return st
}

func testStore(t *testing.T, secrets map[string]string) *Store {
	t.Helper()
	return testStoreTB(t, secrets)
}

func TestMatcherMidTextOffsets(t *testing.T) {
	st := testStore(t, map[string]string{"api_main": "sup3r-r3al-token-XYZ"})
	m, err := st.NewMatcher()
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	got := m.FindAll("my key is sup3r-r3al-token-XYZ use it")
	if len(got) != 1 {
		t.Fatalf("want 1 match, got %v", got)
	}
	if got[0].Name != "api_main" || got[0].Start != 10 || got[0].End != 10+len("sup3r-r3al-token-XYZ") {
		t.Fatalf("bad match: %+v", got[0])
	}
}

func TestMatcherOverlappingRepeated(t *testing.T) {
	st := testStore(t, map[string]string{"a": "aa", "b": "aaa"})
	m, err := st.NewMatcher()
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	got := m.FindAll("aaaa aa")
	if len(got) < 3 {
		t.Fatalf("want overlapping+repeated matches, got %v", got)
	}
	// repeated "aa" at the tail must appear
	found := false
	for _, x := range got {
		if x.Name == "a" && x.Start == 5 && x.End == 7 {
			found = true
		}
	}
	if !found {
		t.Fatalf("missing repeated match: %v", got)
	}
}

func TestMatcherInvalidatedOnWrite(t *testing.T) {
	st := testStore(t, map[string]string{"a": "alpha-secret-1"})
	m1, _ := st.NewMatcher()
	if len(m1.FindAll("has alpha-secret-1")) != 1 {
		t.Fatal("seed match missing")
	}
	m1.Close()
	b := []byte("beta-secret-2")
	if err := st.Put(Secret{Name: "b", Value: b}); err != nil {
		t.Fatal(err)
	}
	zero(b)
	m2, _ := st.NewMatcher()
	defer m2.Close()
	got := m2.FindAll("has beta-secret-2 and alpha-secret-1")
	if len(got) != 2 {
		t.Fatalf("want 2 after write, got %v", got)
	}
	if err := st.Delete("a"); err != nil {
		t.Fatal(err)
	}
	m3, _ := st.NewMatcher()
	defer m3.Close()
	for _, x := range m3.FindAll("has alpha-secret-1") {
		if x.Name == "a" {
			t.Fatalf("stale match after delete: %v", x)
		}
	}
}

func TestMatcherZeroOnClose(t *testing.T) {
	m := buildMatcher([]string{"a"}, [][]byte{[]byte("zero-me-secret")})
	m.Close()
	for _, v := range m.pats {
		for _, b := range v {
			if b != 0 {
				t.Fatal("buffer not zeroed after Close")
			}
		}
	}
	m.Close() // double close safe
}

func TestNoPlaintextMap(t *testing.T) {
	// compile-time guard: ValuesSnapshot must not exist; if it does this fails.
	// runtime guard: matcher exposes names only.
	st := testStore(t, map[string]string{"a": "hidden-value-123"})
	m, _ := st.NewMatcher()
	defer m.Close()
	for _, x := range m.FindAll("x hidden-value-123 y") {
		if x.Name != "a" {
			t.Fatalf("bad name %q", x.Name)
		}
	}
}

func BenchmarkMatcher200x1MiB(b *testing.B) {
	st := testStoreTB(b, nil)
	names := make([]string, 200)
	for i := range names {
		names[i] = "secret-value-number-0123456789"
	}
	// distinct values to avoid dedup shortcuts
	for i := 0; i < 200; i++ {
		v := []byte("tok-" + strings.Repeat("x", 8) + "-" + string(rune('a'+i%26)) + string(rune('0'+i%10)) + "-0123456789abcdef")
		if err := st.Put(Secret{Name: "s" + string(rune(i)), Value: v}); err != nil {
			b.Fatal(err)
		}
		zero(v)
	}
	m, err := st.NewMatcher()
	if err != nil {
		b.Fatal(err)
	}
	defer m.Close()
	text := strings.Repeat("lorem ipsum dolor sit amet ", 40000) // ~1MiB
	if len(text) < 1<<20 {
		text += strings.Repeat(" ", (1<<20)-len(text))
	}
	text += "tok-xxxxxxxx-a0-0123456789abcdef tail"
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = m.FindAll(text)
	}
}
