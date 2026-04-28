package token

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"auth-service/internal/auth"

	pasetov4 "zntr.io/paseto/v4"
)

const (
	ed25519PublicKeyLen  = 32
	ed25519PrivateKeyLen = 64
)

var (
	ErrInvalidKey   = errors.New("invalid paseto v4 key")
	ErrInvalidToken = errors.New("invalid token")
)

// PasetoV4PublicIssuer issues/validates v4.public PASETOs using an Ed25519 keypair.
type PasetoV4PublicIssuer struct {
	private ed25519.PrivateKey
	public  ed25519.PublicKey
}

type v4Payload struct {
	TokenID         string        `json:"jti"`
	UserID          int64         `json:"user_id"`
	Email           string        `json:"email"`
	TokenVersion    int           `json:"token_version"`
	Provider        auth.Provider `json:"provider"`
	ProviderSubject string        `json:"provider_subject"`
	IssuedAt        time.Time     `json:"iat"`
	ExpiresAt       time.Time     `json:"exp"`
}

func NewPasetoV4PublicIssuer(privateKeyBase64, publicKeyBase64 string) (*PasetoV4PublicIssuer, error) {
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

	return &PasetoV4PublicIssuer{private: private, public: public}, nil
}

func (i *PasetoV4PublicIssuer) Issue(ctx context.Context, claims auth.TokenClaims) (string, error) {
	_ = ctx

	payload := v4Payload{
		TokenID:         claims.TokenID,
		UserID:          claims.UserID,
		Email:           strings.TrimSpace(claims.Email),
		TokenVersion:    claims.TokenVersion,
		Provider:        claims.Provider,
		ProviderSubject: claims.ProviderSubject,
		IssuedAt:        claims.IssuedAt.UTC(),
		ExpiresAt:       claims.ExpiresAt.UTC(),
	}

	raw, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}

	token, err := pasetov4.Sign(raw, i.private, nil, nil)
	if err != nil {
		return "", err
	}
	return token, nil
}

func (i *PasetoV4PublicIssuer) Verify(ctx context.Context, token string) (auth.TokenClaims, error) {
	_ = ctx

	msg, err := pasetov4.Verify(token, i.public, nil, nil)
	if err != nil {
		return auth.TokenClaims{}, ErrInvalidToken
	}

	var payload v4Payload
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
		TokenVersion:    payload.TokenVersion,
		IssuedAt:        payload.IssuedAt,
		ExpiresAt:       payload.ExpiresAt,
		Provider:        payload.Provider,
		ProviderSubject: payload.ProviderSubject,
	}, nil
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

var _ auth.TokenIssuer = (*PasetoV4PublicIssuer)(nil)
