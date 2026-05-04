package keygenerator

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"io"
)

// Pair holds one PASETO v4 ed25519 keypair in raw and base64-encoded forms.
type Pair struct {
	PrivateKeyRaw    []byte
	PublicKeyRaw     []byte
	PrivateKeyBase64 string
	PublicKeyBase64  string
}

// Generator creates PASETO-compatible ed25519 keypairs.
type Generator struct {
	rand io.Reader
}

// New returns a generator backed by crypto/rand.
func New() *Generator {
	return &Generator{rand: rand.Reader}
}

// NewWithReader allows tests or callers to inject a deterministic reader.
func NewWithReader(r io.Reader) *Generator {
	if r == nil {
		r = rand.Reader
	}
	return &Generator{rand: r}
}

// Generate creates a fresh ed25519 keypair suitable for PASETO v4 public tokens.
func (g *Generator) Generate(ctx context.Context) (Pair, error) {
	_ = ctx

	reader := rand.Reader
	if g != nil && g.rand != nil {
		reader = g.rand
	}

	publicKey, privateKey, err := ed25519.GenerateKey(reader)
	if err != nil {
		return Pair{}, err
	}

	return Pair{
		PrivateKeyRaw:    append([]byte(nil), privateKey...),
		PublicKeyRaw:     append([]byte(nil), publicKey...),
		PrivateKeyBase64: base64.StdEncoding.EncodeToString(privateKey),
		PublicKeyBase64:  base64.StdEncoding.EncodeToString(publicKey),
	}, nil
}
