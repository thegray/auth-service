package token

import (
	"context"
	"errors"
	"strconv"
	"strings"
	"time"

	"auth-service/internal/auth"

	paseto "aidanwoods.dev/go-paseto"
)

const (
	refreshTokenType = "refresh"
)

var ErrInvalidTokenType = errors.New("invalid token type")

// PasetoV4PublicKIDIssuer issues/validates v4.public PASETOs using an Ed25519 keypair and a footer key id (kid).
type PasetoV4PublicKIDIssuer struct {
	kid    string
	secret paseto.V4AsymmetricSecretKey
	public paseto.V4AsymmetricPublicKey
	parser paseto.Parser
}

func NewPasetoV4PublicKIDIssuer(kid, privateKeyBase64, publicKeyBase64 string) (*PasetoV4PublicKIDIssuer, error) {
	kid = strings.TrimSpace(kid)
	if kid == "" {
		return nil, ErrInvalidKey
	}

	secret, public, err := loadV4Keypair(privateKeyBase64, publicKeyBase64)
	if err != nil {
		return nil, err
	}

	return &PasetoV4PublicKIDIssuer{
		kid:    kid,
		secret: secret,
		public: public,
		parser: paseto.NewParserForValidNow(),
	}, nil
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

	token := paseto.NewToken()
	token.SetJti(strings.TrimSpace(claims.ID))
	token.SetSubject(strings.TrimSpace(claims.Subject))

	// Apply 1-minute leeway for clock skew
	iat := claims.IssuedAt.UTC().Add(-1 * time.Minute)
	token.SetIssuedAt(iat)
	token.SetNotBefore(iat)
	token.SetExpiration(claims.ExpiresAt.UTC())
	token.SetFooter([]byte(i.kid))

	if err := token.Set("v", claims.Version); err != nil {
		return "", err
	}
	token.SetString("typ", claims.Type)

	return token.V4Sign(i.secret, nil), nil
}

func (i *PasetoV4PublicKIDIssuer) Verify(ctx context.Context, token string) (auth.RefreshTokenClaims, error) {
	_ = ctx

	parsed, err := i.parser.ParseV4Public(i.public, token, nil)
	if err != nil {
		return auth.RefreshTokenClaims{}, ErrInvalidToken
	}
	if i.kid != "" && string(parsed.Footer()) != i.kid {
		return auth.RefreshTokenClaims{}, ErrInvalidToken
	}

	id, err := parsed.GetJti()
	if err != nil || strings.TrimSpace(id) == "" {
		return auth.RefreshTokenClaims{}, ErrInvalidToken
	}
	subject, err := parsed.GetSubject()
	if err != nil || strings.TrimSpace(subject) == "" {
		return auth.RefreshTokenClaims{}, ErrInvalidToken
	}
	typ, err := parsed.GetString("typ")
	if err != nil {
		return auth.RefreshTokenClaims{}, ErrInvalidToken
	}
	if strings.TrimSpace(typ) != refreshTokenType {
		return auth.RefreshTokenClaims{}, ErrInvalidTokenType
	}

	var version int
	if err := parsed.Get("v", &version); err != nil {
		return auth.RefreshTokenClaims{}, ErrInvalidToken
	}
	if _, err := strconv.ParseInt(subject, 10, 64); err != nil {
		return auth.RefreshTokenClaims{}, ErrInvalidToken
	}

	issuedAt, err := parsed.GetIssuedAt()
	if err != nil {
		return auth.RefreshTokenClaims{}, ErrInvalidToken
	}
	expiresAt, err := parsed.GetExpiration()
	if err != nil {
		return auth.RefreshTokenClaims{}, ErrInvalidToken
	}

	return auth.RefreshTokenClaims{
		ID:        id,
		Subject:   subject,
		Version:   version,
		Type:      typ,
		IssuedAt:  issuedAt.UTC(),
		ExpiresAt: expiresAt.UTC(),
	}, nil
}

var _ auth.RefreshTokenIssuer = (*PasetoV4PublicKIDIssuer)(nil)
