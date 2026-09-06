package broker

import (
	"context"
	"io"
	"strings"
	"testing"
	"time"

	"sentinel/internal/policy"
)

func testReq(secret, consumer, dest string) Request {
	return Request{Secret: secret, Consumer: consumer, Dest: dest, Reason: "env injection", Requested: time.Now()}
}

func TestFirstMatchWins(t *testing.T) {
	appr := policy.Approvals{
		Default: "allow",
		Rules: []policy.ApprovalRule{
			{Secret: "prod_*", Decision: "deny"},
			{Secret: "prod_token", Decision: "allow", TTL: "15m"},
		},
	}
	b := NewPolicy(appr, nil)
	dec, err := b.Ask(context.Background(), testReq("prod_token", "mcp:dev:node", "node"))
	if err != nil {
		t.Fatal(err)
	}
	if dec.Allow {
		t.Fatal("prod_* deny must beat later allow (first match wins)")
	}
}

func TestGlobSecretConsumer(t *testing.T) {
	appr := policy.Approvals{
		Default: "deny",
		Rules: []policy.ApprovalRule{
			{Name: "dev-github", Secret: "github_*", Consumer: "mcp:dev:*", Decision: "allow", TTL: "15m"},
		},
	}
	var events []string
	b := NewPolicy(appr, func(ev string, _ Request, _ Decision) { events = append(events, ev) })
	dec, _ := b.Ask(context.Background(), testReq("github_token", "mcp:dev:node", "api.github.com"))
	if !dec.Allow || dec.Rule != "dev-github" || dec.TTL != 15*time.Minute {
		t.Fatalf("allow rule must resolve with name+TTL, got %+v", dec)
	}
	dec2, _ := b.Ask(context.Background(), testReq("github_token", "mcp:prod:node", "api.github.com"))
	if dec2.Allow {
		t.Fatal("non-matching consumer must fall to default deny")
	}
	if len(events) != 2 || events[0] != EventApproved || events[1] != EventDenied {
		t.Fatalf("audit events: %v", events)
	}
}

func TestTTLExpiryReasks(t *testing.T) {
	appr := policy.Approvals{
		Default: "deny",
		Rules:   []policy.ApprovalRule{{Secret: "t", Decision: "allow", TTL: "50ms"}},
	}
	asks := 0
	b := NewPolicy(appr, nil)
	b.now = func() time.Time { return time.Now() }
	if _, err := b.Ask(context.Background(), testReq("t", "c", "d")); err != nil {
		t.Fatal(err)
	}
	asks++
	time.Sleep(60 * time.Millisecond)
	dec, err := b.Ask(context.Background(), testReq("t", "c", "d"))
	if err != nil || !dec.Allow {
		t.Fatalf("expired grant must re-ask and allow, got %+v %v", dec, err)
	}
	asks++
	if asks != 2 {
		t.Fatal("expected re-ask after TTL expiry")
	}
}

func TestRateLimit(t *testing.T) {
	appr := policy.Approvals{
		Default:          "deny",
		Rules:            []policy.ApprovalRule{{Secret: "t*", Decision: "allow"}},
		MaxUsesPerMinute: 2,
	}
	var events []string
	b := NewPolicy(appr, func(ev string, _ Request, _ Decision) { events = append(events, ev) })
	ctx := context.Background()
	b.Ask(ctx, testReq("t", "c", "d"))
	b.Ask(ctx, testReq("t2", "c", "d"))
	dec, err := b.Ask(ctx, testReq("t3", "c", "d"))
	if err == nil || dec.Allow {
		t.Fatal("third use must trip rate limit")
	}
	if events[len(events)-1] != EventRateLimited {
		t.Fatalf("must emit approval_rate_limited, got %v", events)
	}
}

func TestDenyDefault(t *testing.T) {
	b := NewPolicy(policy.Approvals{Default: "deny"}, nil)
	dec, _ := b.Ask(context.Background(), testReq("x", "cli", "y"))
	if dec.Allow {
		t.Fatal("default deny must deny")
	}
}

func TestInteractiveAcceptDeny(t *testing.T) {
	ctx := context.Background()
	b := NewInteractive(strings.NewReader("o\n"), io.Discard, 0, nil)
	dec, _ := b.Ask(ctx, testReq("github_token", "mcp:dev:filesystem-mcp", "api.github.com"))
	if !dec.Allow {
		t.Fatal("o must allow")
	}
	b2 := NewInteractive(strings.NewReader("d\n"), io.Discard, 0, nil)
	dec2, _ := b2.Ask(ctx, testReq("github_token", "mcp:dev:filesystem-mcp", "api.github.com"))
	if dec2.Allow {
		t.Fatal("d must deny")
	}
	// EOF => fail closed
	b3 := NewInteractive(strings.NewReader(""), io.Discard, 0, nil)
	dec3, _ := b3.Ask(ctx, testReq("x", "c", "d"))
	if dec3.Allow {
		t.Fatal("EOF must deny")
	}
}

func TestAutoWarns(t *testing.T) {
	var sb strings.Builder
	b := NewAuto(&sb, nil)
	if !strings.Contains(sb.String(), "--yes-i-know") {
		t.Fatal("auto broker must warn")
	}
	dec, _ := b.Ask(context.Background(), testReq("x", "c", "d"))
	if !dec.Allow || dec.Rule != "auto" {
		t.Fatalf("auto must allow, got %+v", dec)
	}
}
