package auth

import (
	"context"
	"time"

	"auth-service/internal/shared"
)

type Clock interface {
	Now() time.Time
}

type UserRepository interface {
	UpsertByProvider(ctx context.Context, provider shared.Provider, subject string, profile shared.ExternalProfile) (*User, error)
	GetByID(ctx context.Context, id int64) (*User, error)
	IncrementTokenVersion(ctx context.Context, userID int64) error
}

// TokenIssuer issues and verifies access tokens
type TokenIssuer interface {
	Issue(ctx context.Context, claims TokenClaims) (string, error)
	Verify(ctx context.Context, token string) (TokenClaims, error)
}

type RefreshTokenIssuer interface {
	Issue(ctx context.Context, claims RefreshTokenClaims) (string, error)
	Verify(ctx context.Context, token string) (RefreshTokenClaims, error)
	KeyID() string
}

// BlacklistStore stores revoked tokens until their expiry.
type BlacklistStore interface {
	Revoke(ctx context.Context, tokenID string, expiresAt time.Time) error
	IsRevoked(ctx context.Context, tokenID string) (bool, error)
}

type RefreshTokenRepository interface {
	Create(ctx context.Context, userID int64, tokenHash string, expiresAt time.Time) error
	DeleteByUser(ctx context.Context, userID int64) error
	GetByHash(ctx context.Context, tokenHash string) (userID int64, expiresAt time.Time, err error)
	DeleteByHash(ctx context.Context, tokenHash string) error
}
