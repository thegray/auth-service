package token

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"auth-service/internal/auth"

	pasetov4 "zntr.io/paseto/v4"
)

const (
	refreshTokenType = "refresh"
)

var ErrInvalidTokenType = errors.New("invalid token type")

// PasetoV4PublicKIDIssuer issues/validates v4.public PASETOs using an Ed25519 keypair and a footer key id (kid).
// The kid is stored in the token footer (base64url-encoded).
type PasetoV4PublicKIDIssuer struct {
	kid     string
	private ed25519.PrivateKey
	public  ed25519.PublicKey
}

func NewPasetoV4PublicKIDIssuer(kid, privateKeyBase64, publicKeyBase64 string) (*PasetoV4PublicKIDIssuer, error) {
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

	return &PasetoV4PublicKIDIssuer{kid: kid, private: private, public: public}, nil
}

func (i *PasetoV4PublicKIDIssuer) KeyID() string { return i.kid }

func (i *PasetoV4PublicKIDIssuer) Issue(ctx context.Context, claims auth.RefreshTokenClaims) (string, error) {
	_ = ctx

	if strings.TrimSpace(claims.Type) == "" {
		claims.Type = refreshTokenType
	}
	if claims.Type != refreshTokenType {
		return "", ErrInvalidTokenType
	}

	raw, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}

	footer := []byte(i.kid)
	token, err := pasetov4.Sign(raw, i.private, footer, nil)
	if err != nil {
		return "", err
	}
	return token, nil
}

func (i *PasetoV4PublicKIDIssuer) Verify(ctx context.Context, token string) (auth.RefreshTokenClaims, error) {
	_ = ctx

	footer, err := extractFooter(token)
	if err != nil {
		return auth.RefreshTokenClaims{}, ErrInvalidToken
	}
	if i.kid != "" && string(footer) != i.kid {
		return auth.RefreshTokenClaims{}, ErrInvalidToken
	}

	msg, err := pasetov4.Verify(token, i.public, footer, nil)
	if err != nil {
		return auth.RefreshTokenClaims{}, ErrInvalidToken
	}

	var claims auth.RefreshTokenClaims
	if err := json.Unmarshal(msg, &claims); err != nil {
		return auth.RefreshTokenClaims{}, ErrInvalidToken
	}

	if strings.TrimSpace(claims.Type) != refreshTokenType {
		return auth.RefreshTokenClaims{}, ErrInvalidTokenType
	}
	if strings.TrimSpace(claims.ID) == "" || strings.TrimSpace(claims.Subject) == "" {
		return auth.RefreshTokenClaims{}, ErrInvalidToken
	}
	if _, err := strconv.ParseInt(claims.Subject, 10, 64); err != nil {
		return auth.RefreshTokenClaims{}, ErrInvalidToken
	}

	return claims, nil
}

var _ auth.RefreshTokenIssuer = (*PasetoV4PublicKIDIssuer)(nil)
