package broker

import (
	"context"
	"time"
)

// Request is one secret-resolution request.
type Request struct {
	Secret    string
	Consumer  string // "mcp:<profile>:<child argv0>" | "egress:<host>" | "gui" | "cli"
	Dest      string // host or tool name
	Reason    string // "env injection" | "header substitution" | ...
	Requested time.Time
}

// Decision is the broker verdict.
type Decision struct {
	Allow bool
	TTL   time.Duration // 0 = single use
	Scope string        // "once" | "session" | "until"
	Rule  string        // which policy rule or "interactive" / "auto"
}

// Broker gates every decrypt-for-injection.
type Broker interface {
	Ask(context.Context, Request) (Decision, error)
}

// Exit code for approval denial in --strict mode.
const ExitApprovalDenied = 4

// Event names emitted to the audit log.
const (
	EventApproved    = "approval_granted"
	EventDenied      = "approval_denied"
	EventRateLimited = "approval_rate_limited"
)
