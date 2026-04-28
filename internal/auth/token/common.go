package token

import (
	"encoding/base64"
	"errors"
	"strings"
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
