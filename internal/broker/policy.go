package broker

import (
	"context"
	"errors"
	"path"
	"sync"
	"time"

	"sentinel/internal/policy"
)

// grant is one cached allow decision.
type grant struct {
	expires time.Time
	rule    string
}

// PolicyBroker decides from policy.yaml without a human.
// Grant cache key: (secret, consumer, dest), in memory only, never on disk.
type PolicyBroker struct {
	mu     sync.Mutex
	appr   policy.Approvals
	grants map[[3]string]grant
	uses   []time.Time // allow timestamps for rate limiting
	now    func() time.Time
	emit   func(event string, req Request, dec Decision)
}

// NewPolicy creates a Policy broker. emit may be nil.
func NewPolicy(appr policy.Approvals, emit func(string, Request, Decision)) *PolicyBroker {
	return &PolicyBroker{appr: appr, grants: map[[3]string]grant{}, now: time.Now, emit: emit}
}

func (b *PolicyBroker) log(event string, req Request, dec Decision) {
	if b.emit != nil {
		b.emit(event, req, dec)
	}
}

// match reports whether a rule matches. Empty fields match anything;
// Secret/Consumer support glob, Dest is exact-or-empty.
func match(r policy.ApprovalRule, req Request) bool {
	if r.Secret != "" {
		ok, err := path.Match(r.Secret, req.Secret)
		if err != nil || !ok {
			return false
		}
	}
	if r.Consumer != "" {
		ok, err := path.Match(r.Consumer, req.Consumer)
		if err != nil || !ok {
			return false
		}
	}
	if r.Dest != "" && r.Dest != req.Dest {
		return false
	}
	return true
}

func ruleName(r policy.ApprovalRule) string {
	if r.Name != "" {
		return r.Name
	}
	return "rule"
}

// Ask implements Broker. First matching rule wins; no rule => default
// ("" = allow for legacy compat, documented). ask/unknown default => deny.
func (b *PolicyBroker) Ask(_ context.Context, req Request) (Decision, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	now := b.now()
	key := [3]string{req.Secret, req.Consumer, req.Dest}
	if g, ok := b.grants[key]; ok && now.Before(g.expires) {
		dec := Decision{Allow: true, TTL: time.Until(g.expires), Scope: "session", Rule: g.rule}
		b.log(EventApproved, req, dec)
		return dec, nil
	}
	delete(b.grants, key)

	for _, r := range b.appr.Rules {
		if !match(r, req) {
			continue
		}
		switch r.Decision {
		case "allow":
			if b.appr.MaxUsesPerMinute > 0 {
				cut := now.Add(-time.Minute)
				kept := b.uses[:0]
				for _, t := range b.uses {
					if t.After(cut) {
						kept = append(kept, t)
					}
				}
				b.uses = kept
				if len(b.uses) >= b.appr.MaxUsesPerMinute {
					dec := Decision{Rule: ruleName(r), Scope: "once"}
					b.log(EventRateLimited, req, dec)
					return dec, errors.New("approval rate limit exceeded")
				}
				b.uses = append(b.uses, now)
			}
			ttl := r.TTLDuration()
			dec := Decision{Allow: true, TTL: ttl, Scope: scopeOf(ttl), Rule: ruleName(r)}
			if ttl > 0 {
				b.grants[key] = grant{expires: now.Add(ttl), rule: ruleName(r)}
			}
			b.log(EventApproved, req, dec)
			return dec, nil
		case "deny":
			dec := Decision{Rule: ruleName(r), Scope: "once"}
			b.log(EventDenied, req, dec)
			return dec, nil
		default: // "ask" or unknown => fail closed
			dec := Decision{Rule: ruleName(r), Scope: "once"}
			b.log(EventDenied, req, dec)
			return dec, nil
		}
	}

	switch b.appr.Default {
	case "allow", "":
		dec := Decision{Allow: true, Scope: "once", Rule: "default-allow"}
		b.log(EventApproved, req, dec)
		return dec, nil
	default: // "deny", "ask", unknown => fail closed
		dec := Decision{Scope: "once", Rule: "default-" + b.appr.Default}
		b.log(EventDenied, req, dec)
		return dec, nil
	}
}

func scopeOf(ttl time.Duration) string {
	if ttl == 0 {
		return "once"
	}
	return "until"
}
