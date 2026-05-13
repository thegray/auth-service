package login

import (
	"context"
	"time"

	"auth-service/internal/auth"
	"auth-service/internal/shared"
)

type IDTokenVerifier interface {
	Verify(ctx context.Context, tokenProvider shared.Provider, appID string, idToken string) (subject string, profile shared.ExternalProfile, err error)
}

type UserRepository interface {
	UpsertByProvider(ctx context.Context, provider shared.Provider, subject string, profile shared.ExternalProfile) (*auth.User, error)
}

type RefreshTokenStore interface {
	Create(ctx context.Context, userID int64, tokenHash string, expiresAt time.Time) error
}

type TokenIssuer interface {
	Issue(ctx context.Context, claims auth.TokenClaims) (string, error)
}

type RefreshTokenIssuer interface {
	Issue(ctx context.Context, claims auth.RefreshTokenClaims) (string, error)
}

type Clock interface {
	Now() time.Time
}
