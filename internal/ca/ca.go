package ca

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"sync"
	"time"
)

type Authority struct {
	Cert *x509.Certificate
	Key  *ecdsa.PrivateKey
	PEM  []byte

	mu    sync.Mutex
	cache map[string]tls.Certificate
}

func dataDir() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".sentinel")
}

func LoadOrCreate() (*Authority, error) {
	dir := dataDir()
	certP, keyP := filepath.Join(dir, "ca.pem"), filepath.Join(dir, "ca-key.pem")
	if b1, err1 := os.ReadFile(certP); err1 == nil {
		if b2, err2 := os.ReadFile(keyP); err2 == nil {
			return parse(b1, b2)
		}
	}
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Sentinel Local CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, err
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	kb, _ := x509.MarshalECPrivateKey(key)
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kb})
	os.MkdirAll(dir, 0o700)
	os.WriteFile(certP, certPEM, 0o600)
	os.WriteFile(keyP, keyPEM, 0o600)
	return parse(certPEM, keyPEM)
}

func parse(certPEM, keyPEM []byte) (*Authority, error) {
	b, _ := pem.Decode(certPEM)
	cert, err := x509.ParseCertificate(b.Bytes)
	if err != nil {
		return nil, err
	}
	kb, _ := pem.Decode(keyPEM)
	key, err := x509.ParseECPrivateKey(kb.Bytes)
	if err != nil {
		return nil, err
	}
	return &Authority{Cert: cert, Key: key, PEM: certPEM, cache: map[string]tls.Certificate{}}, nil
}

func (a *Authority) CertFor(host string) (tls.Certificate, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if c, ok := a.cache[host]; ok {
		return c, nil
	}
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: host},
		DNSNames:     []string{host},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, a.Cert, &key.PublicKey, a.Key)
	if err != nil {
		return tls.Certificate{}, err
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	kb, _ := x509.MarshalECPrivateKey(key)
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kb})
	c, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return c, err
	}
	a.cache[host] = c
	return c, nil
}
