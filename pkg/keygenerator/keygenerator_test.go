package keygenerator

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"testing"
)

func TestGenerate(t *testing.T) {
	reader := bytes.NewReader(bytes.Repeat([]byte{0x01}, ed25519.SeedSize))
	pair, err := NewWithReader(reader).Generate(context.Background())
	if err != nil {
		t.Fatalf("Generate err = %v", err)
	}

	privateRaw, err := base64.StdEncoding.DecodeString(pair.PrivateKeyBase64)
	if err != nil {
		t.Fatalf("decode private key = %v", err)
	}
	publicRaw, err := base64.StdEncoding.DecodeString(pair.PublicKeyBase64)
	if err != nil {
		t.Fatalf("decode public key = %v", err)
	}

	if len(privateRaw) != ed25519.PrivateKeySize {
		t.Fatalf("private key size = %d, want %d", len(privateRaw), ed25519.PrivateKeySize)
	}
	if len(publicRaw) != ed25519.PublicKeySize {
		t.Fatalf("public key size = %d, want %d", len(publicRaw), ed25519.PublicKeySize)
	}

	private := ed25519.PrivateKey(privateRaw)
	public := ed25519.PublicKey(publicRaw)
	if !private.Public().(ed25519.PublicKey).Equal(public) {
		t.Fatalf("generated keypair does not match")
	}
}
