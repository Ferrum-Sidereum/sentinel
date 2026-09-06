package broker

import (
	"context"
)

// SecretStore is the decrypt-for-injection path. Only this package calls it:
// mcp inject resolves placeholders exclusively via Resolve (enforced by
// TestOnlyBrokerResolves in resolve_test.go grepping the mcp package).
type SecretStore interface {
	Resolve(name string) (SecretValue, error)
}

// SecretValue carries decrypted material; zero it after use.
type SecretValue struct {
	Value []byte
}

// Resolve asks the broker and, only on Allow, decrypts via the store.
// Denial returns the Decision with Allow=false and no store access.
func Resolve(ctx context.Context, b Broker, st SecretStore, req Request) ([]byte, Decision, error) {
	if b == nil {
		return nil, Decision{Scope: "once", Rule: "no-broker"}, context.DeadlineExceeded
	}
	dec, err := b.Ask(ctx, req)
	if err != nil {
		return nil, dec, err
	}
	if !dec.Allow {
		return nil, dec, nil
	}
	sec, err := st.Resolve(req.Secret)
	if err != nil {
		return nil, dec, err
	}
	return sec.Value, dec, nil
}
