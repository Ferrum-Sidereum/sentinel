package scrubber

import (
	"strings"
	"testing"
	"time"
)

func TestDetectors(t *testing.T) {
	text := "write to ivan@x.ru, card 4111 1111 1111 1111, key sk-abcdefgh12345678, token value AKIAIOSFODNN7EXAMPLE"
	f := Scan(text, nil, nil)
	types := map[string]bool{}
	for _, x := range f {
		types[shortType(x.Type)] = true
	}
	for _, want := range []string{"EMAIL", "CREDIT_CARD", "OPENAI_KEY", "AWS_KEY"} {
		if !types[want] {
			t.Fatalf("missing %s in %v", want, f)
		}
	}
}

func TestMaskAndPseudo(t *testing.T) {
	sess := NewSession(time.Hour)
	text := "contact ivan@x.ru or ivan@x.ru again"
	f := Scan(text, nil, nil)
	masked, _ := Apply(text, f, "mask", sess, 0.7)
	if strings.Contains(masked, "ivan@x.ru") {
		t.Fatal("mask leaked")
	}
	pseudo, _ := Apply(text, f, "pseudonymize", sess, 0.7)
	if strings.Count(pseudo, "<EMAIL_1>") != 2 {
		t.Fatalf("not consistent: %s", pseudo)
	}
	if got := sess.Rehydrate(pseudo); got != text {
		t.Fatalf("rehydrate failed: %s", got)
	}
}

func TestVaultAlwaysMasked(t *testing.T) {
	sess := NewSession(time.Hour)
	f := Scan("the key is hunter2-secret", map[string]string{"s": "hunter2-secret"}, nil)
	out, _ := Apply("the key is hunter2-secret", f, "mask", sess, 0.7)
	if strings.Contains(out, "hunter2-secret") {
		t.Fatal("vault value leaked")
	}
}

func TestLuhnReject(t *testing.T) {
	f := Scan("order 1234 5678 9012 3456", nil, nil)
	for _, x := range f {
		if x.Type == "CREDIT_CARD" {
			t.Fatalf("false positive card: %v", x)
		}
	}
}
