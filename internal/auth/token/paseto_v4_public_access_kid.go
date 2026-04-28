package token

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"auth-service/internal/auth"

	pasetov4 "zntr.io/paseto/v4"
)

type PasetoV4PublicAccessKIDIssuer struct {
	kid     string
	private ed25519.PrivateKey
	public  ed25519.PublicKey
}

type accessPayload struct {
	TokenID         string        `json:"jti"`
	UserID          int64         `json:"user_id"`
	Email           string        `json:"email"`
	Provider        auth.Provider `json:"provider"`
	ProviderSubject string        `json:"provider_subject"`
	IssuedAt        time.Time     `json:"iat"`
	ExpiresAt       time.Time     `json:"exp"`
}

func NewPasetoV4PublicAccessKIDIssuer(kid, privateKeyBase64, publicKeyBase64 string) (*PasetoV4PublicAccessKIDIssuer, error) {
	kid = strings.TrimSpace(kid)
	if kid == "" {
		return nil, fmt.Errorf("%w: kid missing", ErrInvalidKey)
	}

	priv, err := decodeKey(privateKeyBase64, ed25519PrivateKeyLen)
	if err != nil {
		return nil, fmt.Errorf("%w: private", err)
	}
	pub, err := decodeKey(publicKeyBase64, ed25519PublicKeyLen)
	if err != nil {
		return nil, fmt.Errorf("%w: public", err)
	}

	private := ed25519.PrivateKey(priv)
	public := ed25519.PublicKey(pub)
	if !ed25519.PrivateKey(private).Public().(ed25519.PublicKey).Equal(public) {
		return nil, fmt.Errorf("%w: keypair mismatch", ErrInvalidKey)
	}

	return &PasetoV4PublicAccessKIDIssuer{kid: kid, private: private, public: public}, nil
}

func (i *PasetoV4PublicAccessKIDIssuer) Issue(ctx context.Context, claims auth.TokenClaims) (string, error) {
	_ = ctx

	payload := accessPayload{
		TokenID:         strings.TrimSpace(claims.TokenID),
		UserID:          claims.UserID,
		Email:           strings.TrimSpace(claims.Email),
		Provider:        claims.Provider,
		ProviderSubject: strings.TrimSpace(claims.ProviderSubject),
		IssuedAt:        claims.IssuedAt.UTC(),
		ExpiresAt:       claims.ExpiresAt.UTC(),
	}

	raw, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}

	footer := []byte(i.kid)
	return pasetov4.Sign(raw, i.private, footer, nil)
}

func (i *PasetoV4PublicAccessKIDIssuer) Verify(ctx context.Context, token string) (auth.TokenClaims, error) {
	_ = ctx

	footer, err := extractFooter(token)
	if err != nil {
		return auth.TokenClaims{}, ErrInvalidToken
	}
	if i.kid != "" && string(footer) != i.kid {
		return auth.TokenClaims{}, ErrInvalidToken
	}

	msg, err := pasetov4.Verify(token, i.public, footer, nil)
	if err != nil {
		return auth.TokenClaims{}, ErrInvalidToken
	}

	var payload accessPayload
	if err := json.Unmarshal(msg, &payload); err != nil {
		return auth.TokenClaims{}, ErrInvalidToken
	}
	if strings.TrimSpace(payload.TokenID) == "" || payload.UserID == 0 {
		return auth.TokenClaims{}, ErrInvalidToken
	}

	return auth.TokenClaims{
		TokenID:         payload.TokenID,
		UserID:          payload.UserID,
		Email:           payload.Email,
		IssuedAt:        payload.IssuedAt,
		ExpiresAt:       payload.ExpiresAt,
		Provider:        payload.Provider,
		ProviderSubject: payload.ProviderSubject,
	}, nil
}

var _ auth.TokenIssuer = (*PasetoV4PublicAccessKIDIssuer)(nil)
