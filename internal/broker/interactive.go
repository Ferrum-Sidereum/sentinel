package broker

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"strings"
	"time"
)

// InteractiveBroker prompts on the controlling terminal.
type InteractiveBroker struct {
	in     io.Reader
	out    io.Writer
	grant  time.Duration // session-grant cache TTL
	mu     chan struct{}
	emit   func(string, Request, Decision)
	reader *bufio.Reader
}

// NewInteractive creates an Interactive broker; grantCache is the "session"
// grant TTL (<=0 => 15m).
func NewInteractive(in io.Reader, out io.Writer, grantCache time.Duration, emit func(string, Request, Decision)) *InteractiveBroker {
	if grantCache <= 0 {
		grantCache = 15 * time.Minute
	}
	return &InteractiveBroker{in: in, out: out, grant: grantCache, mu: make(chan struct{}, 1), emit: emit}
}

func (b *InteractiveBroker) log(event string, req Request, dec Decision) {
	if b.emit != nil {
		b.emit(event, req, dec)
	}
}

// Ask prompts: agent "X" requests snt://SECRET for DEST — [o]nce / [s]ession / [1]5m / [d]eny?
func (b *InteractiveBroker) Ask(ctx context.Context, req Request) (Decision, error) {
	agent := req.Consumer
	if i := strings.LastIndex(agent, ":"); i >= 0 {
		agent = agent[i+1:]
	}
	fmt.Fprintf(b.out, "agent %q requests snt://%s for %s — [o]nce / [s]ession / [1]5m / [d]eny? ", agent, req.Secret, req.Dest)
	type res struct {
		s   string
		err error
	}
	ch := make(chan res, 1)
	go func() {
		if b.reader == nil {
			b.reader = bufio.NewReader(b.in)
		}
		s, err := b.reader.ReadString('\n')
		ch <- res{s, err}
	}()
	select {
	case <-ctx.Done():
		dec := Decision{Scope: "once", Rule: "interactive"}
		b.log(EventDenied, req, dec)
		return dec, ctx.Err()
	case r := <-ch:
		if r.err != nil {
			dec := Decision{Scope: "once", Rule: "interactive"}
			b.log(EventDenied, req, dec)
			return dec, nil // EOF/no TTY => fail closed deny
		}
		switch strings.ToLower(strings.TrimSpace(r.s)) {
		case "o", "once", "y", "yes":
			dec := Decision{Allow: true, Scope: "once", Rule: "interactive"}
			b.log(EventApproved, req, dec)
			return dec, nil
		case "s", "session":
			dec := Decision{Allow: true, TTL: b.grant, Scope: "session", Rule: "interactive"}
			b.log(EventApproved, req, dec)
			return dec, nil
		case "1", "15m":
			dec := Decision{Allow: true, TTL: 15 * time.Minute, Scope: "until", Rule: "interactive"}
			b.log(EventApproved, req, dec)
			return dec, nil
		default: // "d", "deny", empty, unknown => deny
			dec := Decision{Scope: "once", Rule: "interactive"}
			b.log(EventDenied, req, dec)
			return dec, nil
		}
	}
}
