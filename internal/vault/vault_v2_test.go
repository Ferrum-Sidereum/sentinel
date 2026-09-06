package vault

import (
	"bytes"
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	_ "modernc.org/sqlite"
)

var testKey = bytes.Repeat([]byte{0x42}, 32)

func v2Store(t *testing.T, initial map[string]string) *Store {
	t.Helper()
	return v2StorePath(t, filepath.Join(t.TempDir(), "vault.db"), initial)
}

func v2StorePath(t *testing.T, path string, initial map[string]string) *Store {
	t.Helper()
	st, err := Open(path, testKey)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	for n, v := range initial {
		b := []byte(v)
		if err := st.Put(Secret{Name: n, Value: b}); err != nil {
			t.Fatal(err)
		}
		zero(b)
	}
	return st
}

// buildV1Fixture creates a v1-schema vault.db with known values, encrypted
// with testKey. Returns the path and expected plaintext map.
func buildV1Fixture(t *testing.T, path string) map[string]string {
	t.Helper()
	want := map[string]string{
		"api-key":   "super-secret-value-1",
		"db-pass":   "hunter2-hunter2",
		"comma":     "value-with,comma",
		"empty":     "x",
		"multiline": "line1\nline2",
	}
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.Exec(`CREATE TABLE secrets(
		name TEXT PRIMARY KEY, value BLOB NOT NULL, nonce BLOB NOT NULL,
		kind TEXT, hosts TEXT, paths TEXT, methods TEXT, inject_hdr TEXT,
		version INTEGER, created_at TEXT)`); err != nil {
		t.Fatal(err)
	}
	st := &Store{key: testKey}
	for n, v := range want {
		hosts := "example.com"
		if n == "comma" {
			hosts = "a.com,b.com" // legacy comma-joined with real comma inside? no: two hosts
		}
		ct, nonce, err := st.seal([]byte(v))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := db.Exec(`INSERT INTO secrets(name,value,nonce,kind,hosts,paths,methods,inject_hdr,version,created_at) VALUES(?,?,?,?,?,?,?,?,?,?)`,
			n, ct, nonce, "bearer", hosts, "", "GET", "Authorization", 1, time.Now().UTC().Format(time.RFC3339)); err != nil {
			t.Fatal(err)
		}
	}
	return want
}

func TestMigrateV1ToV2(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "vault.db")
	want := buildV1Fixture(t, path)
	st, err := Open(path, testKey)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if _, err := os.Stat(path + ".v1.bak"); err != nil {
		t.Fatalf("backup missing: %v", err)
	}
	for n, v := range want {
		got, err := st.Get(n)
		if err != nil {
			t.Fatalf("get %s: %v", n, err)
		}
		if string(got.Value) != v {
			t.Fatalf("get %s: got %q want %q", n, got.Value, v)
		}
	}
	var ver string
	if err := st.db.QueryRow(`SELECT value FROM schema_meta WHERE key='schema_version'`).Scan(&ver); err != nil || ver != "2" {
		t.Fatalf("schema version = %q, %v", ver, err)
	}
}

func TestCommaHostRoundTrip(t *testing.T) {
	st := v2Store(t, nil)
	host := "example,com"
	b := []byte("v")
	if err := st.Put(Secret{Name: "c", Value: b, Hosts: []string{host, "other.com"}}); err != nil {
		t.Fatal(err)
	}
	got, err := st.Get("c")
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Hosts) != 2 || got.Hosts[0] != host || got.Hosts[1] != "other.com" {
		t.Fatalf("hosts = %q", got.Hosts)
	}
}

func TestPutPreservesCreatedAt(t *testing.T) {
	st := v2Store(t, nil)
	v1 := []byte("one")
	if err := st.Put(Secret{Name: "a", Value: v1, Version: 1}); err != nil {
		t.Fatal(err)
	}
	first, _ := st.Get("a")
	time.Sleep(1100 * time.Millisecond) // RFC3339 second precision
	v2 := []byte("two")
	if err := st.Put(Secret{Name: "a", Value: v2, Version: 2}); err != nil {
		t.Fatal(err)
	}
	second, _ := st.Get("a")
	if !second.CreatedAt.Equal(first.CreatedAt) {
		t.Fatalf("created_at changed: %v -> %v", first.CreatedAt, second.CreatedAt)
	}
	if !second.UpdatedAt.After(first.UpdatedAt) {
		t.Fatalf("updated_at did not advance: %v -> %v", first.UpdatedAt, second.UpdatedAt)
	}
}

func TestRotateKeep3(t *testing.T) {
	st := v2Store(t, map[string]string{"r": "v0"})
	for i := 1; i <= 5; i++ {
		if err := st.Rotate("r", []byte(fmt.Sprintf("v%d", i)), 3); err != nil {
			t.Fatal(err)
		}
	}
	vers, err := st.Versions("r")
	if err != nil {
		t.Fatal(err)
	}
	if len(vers) != 3 {
		t.Fatalf("want 3 versions, got %v", vers)
	}
	// Rotate archives current version before bump: after 5 rotates the
	// retained archive is [2 3 4], current version is 6.
	if vers[0] != 2 || vers[1] != 3 || vers[2] != 4 {
		t.Fatalf("unexpected versions %v", vers)
	}
	cur, _ := st.Get("r")
	if string(cur.Value) != "v5" || cur.Version != 5 {
		t.Fatalf("current = %q v%d", cur.Value, cur.Version)
	}
}

func TestRollback(t *testing.T) {
	st := v2Store(t, map[string]string{"r": "v0"})
	if err := st.Rotate("r", []byte("v1"), 3); err != nil {
		t.Fatal(err)
	}
	if err := st.Rollback("r"); err != nil {
		t.Fatal(err)
	}
	got, err := st.Get("r")
	if err != nil {
		t.Fatal(err)
	}
	if string(got.Value) != "v0" {
		t.Fatalf("rollback got %q want v0", got.Value)
	}
}

func TestExpiredRefusedAndMarked(t *testing.T) {
	st := v2Store(t, nil)
	past := time.Now().Add(-time.Hour)
	b := []byte("secret")
	if err := st.Put(Secret{Name: "e", Value: b, ExpiresAt: &past}); err != nil {
		t.Fatal(err)
	}
	got, _ := st.Get("e")
	if !got.Expired() {
		t.Fatal("expected expired marker")
	}
	if _, err := st.Resolve("e"); err == nil {
		t.Fatal("expected resolver to refuse expired secret")
	}
	// Unexpired resolves and touches.
	future := time.Now().Add(time.Hour)
	if err := st.Put(Secret{Name: "ok", Value: []byte("v"), ExpiresAt: &future}); err != nil {
		t.Fatal(err)
	}
	res, err := st.Resolve("ok")
	if err != nil {
		t.Fatal(err)
	}
	if res.UseCount != 1 || res.LastUsedAt == nil {
		t.Fatalf("touch missing: %+v", res)
	}
}

func TestConcurrentWrites(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "vault.db")
	st := v2StorePath(t, path, nil)
	var wg sync.WaitGroup
	errs := make([]error, 8)
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			name := fmt.Sprintf("k%d", i%2)
			for j := 0; j < 25; j++ {
				v := []byte(fmt.Sprintf("v-%d-%d", i, j))
				if err := st.Put(Secret{Name: name, Value: v}); err != nil {
					errs[i] = err
					return
				}
			}
		}(i)
	}
	wg.Wait()
	for _, e := range errs {
		if e != nil {
			t.Fatalf("concurrent write: %v", e)
		}
	}
}

func TestTwoProcessesNoBusy(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "vault.db")
	a, err := Open(path, testKey)
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	b, err := Open(path, testKey)
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	var wg sync.WaitGroup
	var ea, eb error
	wg.Add(2)
	go func() {
		defer wg.Done()
		for i := 0; i < 20 && ea == nil; i++ {
			ea = a.Put(Secret{Name: "pa", Value: []byte(fmt.Sprintf("a%d", i))})
		}
	}()
	go func() {
		defer wg.Done()
		for i := 0; i < 20 && eb == nil; i++ {
			eb = b.Put(Secret{Name: "pb", Value: []byte(fmt.Sprintf("b%d", i))})
		}
	}()
	wg.Wait()
	if ea != nil || eb != nil {
		t.Fatalf("two processes: %v %v", ea, eb)
	}
}
