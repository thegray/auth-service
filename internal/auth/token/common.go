package token

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"strings"

	paseto "aidanwoods.dev/go-paseto"
)

const (
	ed25519PublicKeyLen  = 32
	ed25519PrivateKeyLen = 64
)

var (
	ErrInvalidKey   = errors.New("invalid paseto v4 key")
	ErrInvalidToken = errors.New("invalid token")
)

// extractFooter decodes the optional footer for v4.public tokens.
// v4.public.payload.sig[.footer]
func extractFooter(token string) ([]byte, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 4 && len(parts) != 5 {
		return nil, ErrInvalidToken
	}
	if len(parts) == 4 {
		return nil, nil
	}

	footerPart := parts[4]
	footerRaw, err := base64.RawURLEncoding.DecodeString(footerPart)
	if err != nil {
		return nil, ErrInvalidToken
	}
	return footerRaw, nil
}

func decodeKey(base64Value string, wantLen int) ([]byte, error) {
	base64Value = strings.TrimSpace(base64Value)
	if base64Value == "" {
		return nil, ErrInvalidKey
	}
	raw, err := base64.StdEncoding.DecodeString(base64Value)
	if err != nil {
		return nil, ErrInvalidKey
	}
	if len(raw) != wantLen {
		return nil, ErrInvalidKey
	}
	return raw, nil
}

func loadV4Keypair(privateKeyBase64, publicKeyBase64 string) (paseto.V4AsymmetricSecretKey, paseto.V4AsymmetricPublicKey, error) {
	priv, err := decodeKey(privateKeyBase64, ed25519PrivateKeyLen)
	if err != nil {
		return paseto.V4AsymmetricSecretKey{}, paseto.V4AsymmetricPublicKey{}, err
	}
	pub, err := decodeKey(publicKeyBase64, ed25519PublicKeyLen)
	if err != nil {
		return paseto.V4AsymmetricSecretKey{}, paseto.V4AsymmetricPublicKey{}, err
	}

	secret, err := paseto.NewV4AsymmetricSecretKeyFromEd25519(ed25519.PrivateKey(priv))
	if err != nil {
		return paseto.V4AsymmetricSecretKey{}, paseto.V4AsymmetricPublicKey{}, err
	}
	public, err := paseto.NewV4AsymmetricPublicKeyFromEd25519(ed25519.PublicKey(pub))
	if err != nil {
		return paseto.V4AsymmetricSecretKey{}, paseto.V4AsymmetricPublicKey{}, err
	}

	if !bytes.Equal(secret.Public().ExportBytes(), public.ExportBytes()) {
		return paseto.V4AsymmetricSecretKey{}, paseto.V4AsymmetricPublicKey{}, ErrInvalidKey
	}

	return secret, public, nil
}
