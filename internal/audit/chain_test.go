package audit

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestVerifyPass(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "audit.jsonl")
	l, err := Open(p)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 5; i++ {
		l.Log("", "env_imported", map[string]any{"count": i, "host": "h"})
	}
	l.Close()
	if err := Verify(p); err != nil {
		t.Fatalf("verify: %v", err)
	}
}

func TestVerifyFailByteFlip(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "audit.jsonl")
	l, _ := Open(p)
	l.Log("", "secret_added", map[string]any{"name": "API_KEY"})
	l.Log("", "secret_added", map[string]any{"name": "OTHER"})
	l.Close()
	b, _ := os.ReadFile(p)
	lines := strings.Split(strings.TrimRight(string(b), "\n"), "\n")
	// flip a byte in second record
	if len(lines) >= 2 {
		r := []byte(lines[1])
		r[10] ^= 0xff
		lines[1] = string(r)
	}
	os.WriteFile(p, []byte(strings.Join(lines, "\n")+"\n"), 0o600)
	err := Verify(p)
	if err == nil {
		t.Fatal("expected chain break")
	}
	if !strings.Contains(err.Error(), "seq 2") {
		t.Fatalf("must name record seq, got: %v", err)
	}
}

func TestRotationContinuity(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "audit.jsonl")
	l, _ := Open(p, WithMaxSize(10))
	l.Log("", "env_imported", map[string]any{"count": 1})
	l.Log("", "env_imported", map[string]any{"count": 2}) // triggers rotate
	l.Log("", "env_imported", map[string]any{"count": 3})
	l.Close()
	files := ChainFilesFor(p)
	if len(files) < 2 {
		t.Fatalf("expected rotated files, got %v", files)
	}
	recs, err := ReadAll(files)
	if err != nil {
		t.Fatal(err)
	}
	if len(recs) != 3 {
		t.Fatalf("expected 3 records across files, got %d", len(recs))
	}
	prev := zeroHash
	for _, r := range recs {
		if r.PrevHash != prev || ComputeHash(r) != r.Hash {
			t.Fatalf("chain broken at seq %d", r.Seq)
		}
		prev = r.Hash
	}
}

func TestTailSeesOtherProcess(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "audit.jsonl")
	l1, _ := Open(p)
	l1.Log("", "env_imported", map[string]any{"count": 1})
	l1.Close()
	stop := make(chan struct{})
	got := make(chan Record, 1)
	go func() {
		TailPoll(ChainFilesFor(p), CurrentSeq(ChainFilesFor(p)), time.Time{}, "", "", stop, func(r Record) {
			got <- r
		})
	}()
	time.Sleep(50 * time.Millisecond)
	l2, _ := Open(p)
	l2.Log("", "secret_added", map[string]any{"name": "LATE"})
	l2.Close()
	select {
	case r := <-got:
		if r.Type != "secret_added" {
			t.Fatalf("wrong record: %s", r.Type)
		}
	case <-time.After(200 * time.Millisecond):
		t.Fatal("tail did not see other process write in 200ms")
	}
	close(stop)
}

func TestRetentionPrunes(t *testing.T) {
	dir := t.TempDir()
	// fake old rotated files
	for _, n := range []string{"audit.20200101-000000.jsonl", "audit.20200102-000000.jsonl"} {
		fp := filepath.Join(dir, n)
		os.WriteFile(fp, []byte("{}\n"), 0o600)
		old := time.Now().Add(-100 * 24 * time.Hour)
		os.Chtimes(fp, old, old)
	}
	Prune(dir, "audit", 30*24*time.Hour, 0)
	entries, _ := os.ReadDir(dir)
	if len(entries) != 0 {
		t.Fatalf("expected age prune, left %d", len(entries))
	}
	// size prune
	for _, n := range []string{"audit.20260101-000001.jsonl", "audit.20260101-000002.jsonl"} {
		os.WriteFile(filepath.Join(dir, n), []byte(strings.Repeat("x", 1000)+"\n"), 0o600)
	}
	Prune(dir, "audit", 0, 1500)
	entries, _ = os.ReadDir(dir)
	if len(entries) != 1 {
		t.Fatalf("expected size prune to 1 file, left %d", len(entries))
	}
}

func TestValueLikePayloadRejected(t *testing.T) {
	tf := ToTypedFields(map[string]any{"name": "X", "value": "sk-proj-abcdefghijklmnop123456"})
	if tf.Name != "X" {
		t.Fatal("name must pass")
	}
	m := typedToMap(tf)
	if _, ok := m["value"]; ok {
		t.Fatal("secret value must never reach log by construction")
	}
	tf2 := ToTypedFields(map[string]any{"name": "sk-proj-abcdefghijklmnop123456"})
	if tf2.Name != "" {
		t.Fatal("value-like name must be rejected")
	}
}
