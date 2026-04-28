package auth

import (
	"context"
	"time"
)

type Clock interface {
	Now() time.Time
}

type UserRepository interface {
	UpsertByProvider(ctx context.Context, provider Provider, subject string, profile ExternalProfile) (*User, error)
	GetByID(ctx context.Context, id int64) (*User, error)
	IncrementTokenVersion(ctx context.Context, userID int64) error
}

type ExternalProfile struct {
	Email      string
	Name       string
	PictureURL string
}

// ExternalIdentityVerifier verifies an external login credential
type ExternalIdentityVerifier interface {
	Verify(ctx context.Context, credential string) (subject string, profile ExternalProfile, err error)
}

// GoogleIDTokenVerifier is provider-specific to keep Service dependencies explicit.
// For now it's identical to ExternalIdentityVerifier (string in, subject/profile out).
type GoogleIDTokenVerifier interface {
	Verify(ctx context.Context, idToken string) (subject string, profile ExternalProfile, err error)
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
