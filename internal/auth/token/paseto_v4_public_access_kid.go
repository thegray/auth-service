package token

import (
	"context"
	"strings"
	"time"

	"auth-service/internal/auth"
	applogger "auth-service/pkg/logger"

	paseto "aidanwoods.dev/go-paseto"
	"go.uber.org/zap"
)

type PasetoV4PublicAccessKIDIssuer struct {
	kid    string
	secret paseto.V4AsymmetricSecretKey
	public paseto.V4AsymmetricPublicKey
	parser paseto.Parser
	log    *applogger.Logger
}

func NewPasetoV4PublicAccessKIDIssuer(kid, privateKeyBase64, publicKeyBase64 string, log *applogger.Logger) (*PasetoV4PublicAccessKIDIssuer, error) {
	if log == nil {
		log = applogger.Wrap(zap.NewNop())
	}

	kid = strings.TrimSpace(kid)
	if kid == "" {
		return nil, ErrInvalidKey
	}

	secret, public, err := loadV4Keypair(privateKeyBase64, publicKeyBase64)
	if err != nil {
		return nil, err
	}

	return &PasetoV4PublicAccessKIDIssuer{
		kid:    kid,
		secret: secret,
		public: public,
		parser: paseto.NewParserForValidNow(),
		log:    log.Named("paseto-access-kid"),
	}, nil
}

func (i *PasetoV4PublicAccessKIDIssuer) Issue(ctx context.Context, claims auth.TokenClaims) (string, error) {
	_ = ctx

	token := paseto.NewToken()
	token.SetJti(strings.TrimSpace(claims.TokenID))

	// Apply 1-minute leeway for clock skew
	iat := claims.IssuedAt.UTC().Add(-1 * time.Minute)
	token.SetIssuedAt(iat)
	token.SetNotBefore(iat)
	token.SetExpiration(claims.ExpiresAt.UTC())
	token.SetFooter([]byte(i.kid))

	if err := token.Set("user_id", claims.UserID); err != nil {
		return "", err
	}
	token.SetString("email", strings.TrimSpace(claims.Email))
	token.SetString("provider", string(claims.Provider))
	token.SetString("provider_subject", strings.TrimSpace(claims.ProviderSubject))

	return token.V4Sign(i.secret, nil), nil
}

func (i *PasetoV4PublicAccessKIDIssuer) Verify(ctx context.Context, token string) (auth.TokenClaims, error) {
	_ = ctx

	parsed, err := i.parser.ParseV4Public(i.public, token, nil)
	if err != nil {
		i.log.WarnCtx(ctx, "failed to parse v4 public access token", zap.Error(err))
		return auth.TokenClaims{}, ErrInvalidToken
	}
	if i.kid != "" && string(parsed.Footer()) != i.kid {
		return auth.TokenClaims{}, ErrInvalidToken
	}

	tokenID, err := parsed.GetJti()
	if err != nil || strings.TrimSpace(tokenID) == "" {
		return auth.TokenClaims{}, ErrInvalidToken
	}

	var userID int64
	if err := parsed.Get("user_id", &userID); err != nil || userID <= 0 {
		return auth.TokenClaims{}, ErrInvalidToken
	}

	email, err := parsed.GetString("email")
	if err != nil {
		return auth.TokenClaims{}, ErrInvalidToken
	}
	provider, err := parsed.GetString("provider")
	if err != nil {
		return auth.TokenClaims{}, ErrInvalidToken
	}
	providerSubject, err := parsed.GetString("provider_subject")
	if err != nil {
		return auth.TokenClaims{}, ErrInvalidToken
	}
	issuedAt, err := parsed.GetIssuedAt()
	if err != nil {
		return auth.TokenClaims{}, ErrInvalidToken
	}
	expiresAt, err := parsed.GetExpiration()
	if err != nil {
		return auth.TokenClaims{}, ErrInvalidToken
	}

	return auth.TokenClaims{
		TokenID:         tokenID,
		UserID:          userID,
		Email:           strings.TrimSpace(email),
		IssuedAt:        issuedAt.UTC(),
		ExpiresAt:       expiresAt.UTC(),
		Provider:        auth.Provider(strings.TrimSpace(provider)),
		ProviderSubject: strings.TrimSpace(providerSubject),
	}, nil
}

var _ auth.TokenIssuer = (*PasetoV4PublicAccessKIDIssuer)(nil)
