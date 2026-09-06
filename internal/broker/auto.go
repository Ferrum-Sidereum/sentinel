package broker

import (
	"context"
	"errors"
	"fmt"
	"io"
)

// AutoBroker allows everything. Only for tests/demos; requires explicit opt-in.
type AutoBroker struct {
	out  io.Writer
	emit func(string, Request, Decision)
}

// NewAuto creates an allow-all broker and prints a warning. Never the default;
// callers must gate it behind --yes-i-know.
func NewAuto(out io.Writer, emit func(string, Request, Decision)) *AutoBroker {
	if out != nil {
		fmt.Fprintln(out, "WARNING: approval broker in auto-allow mode (--yes-i-know); every secret request is granted")
	}
	return &AutoBroker{out: out, emit: emit}
}

func (b *AutoBroker) Ask(_ context.Context, req Request) (Decision, error) {
	if b == nil {
		return Decision{}, errors.New("no broker configured")
	}
	dec := Decision{Allow: true, Scope: "once", Rule: "auto"}
	if b.emit != nil {
		b.emit(EventApproved, req, dec)
	}
	return dec, nil
}
