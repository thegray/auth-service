package auth

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"
	"time"

	"github.com/google/uuid"
)

var (
	ErrInvalidCredential = errors.New("invalid credential")
	ErrUnauthorized      = errors.New("unauthorized")
	ErrTokenRevoked      = errors.New("token revoked")
)

const (
	defaultAccessTTL  = 15 * time.Minute
	defaultRefreshTTL = 30 * 24 * time.Hour
)

type Service struct {
	users          UserRepository
	refreshTokens  RefreshTokenRepository
	googleVerifier GoogleIDTokenVerifier
	tokens         TokenIssuer
	blacklist      BlacklistStore
	clock          Clock
	ttl            time.Duration
	refreshTTL     time.Duration
}

type serviceClock struct{}

func (serviceClock) Now() time.Time { return time.Now() }

func NewService(users UserRepository, refreshTokens RefreshTokenRepository, googleVerifier GoogleIDTokenVerifier, tokens TokenIssuer, blacklist BlacklistStore, ttl, refreshTTL time.Duration) *Service {
	if ttl <= 0 {
		ttl = defaultAccessTTL
	}
	if refreshTTL <= 0 {
		refreshTTL = defaultRefreshTTL
	}

	var clock Clock = serviceClock{}
	return &Service{
		users:          users,
		refreshTokens:  refreshTokens,
		googleVerifier: googleVerifier,
		tokens:         tokens,
		blacklist:      blacklist,
		clock:          clock,
		ttl:            ttl,
		refreshTTL:     refreshTTL,
	}
}

func (s *Service) LoginWithGoogle(ctx context.Context, idToken string) (LoginResult, error) {
	if strings.TrimSpace(idToken) == "" {
		return LoginResult{}, ErrInvalidCredential
	}

	if s.googleVerifier == nil {
		return LoginResult{}, ErrInvalidCredential
	}

	subject, profile, err := s.googleVerifier.Verify(ctx, idToken)
	if err != nil || strings.TrimSpace(subject) == "" {
		return LoginResult{}, ErrInvalidCredential
	}

	now := s.clock.Now().UTC()
	user, err := s.users.UpsertByProvider(ctx, ProviderGoogle, subject, profile)
	if err != nil {
		return LoginResult{}, err
	}

	claims := TokenClaims{
		TokenID:         uuid.NewString(),
		UserID:          user.ID,
		Email:           user.Email,
		TokenVersion:    user.TokenVersion,
		IssuedAt:        now,
		ExpiresAt:       now.Add(s.ttl),
		Provider:        ProviderGoogle,
		ProviderSubject: subject,
	}

	token, err := s.tokens.Issue(ctx, claims)
	if err != nil {
		return LoginResult{}, err
	}

	refreshToken := uuid.NewString()
	if s.refreshTokens != nil {
		refreshHash := hashToken(refreshToken)
		if err := s.refreshTokens.Create(ctx, user.ID, refreshHash, now.Add(s.refreshTTL)); err != nil {
			return LoginResult{}, err
		}
	}

	return LoginResult{
		AccessToken:  token,
		RefreshToken: refreshToken,
		User:         user,
		ExpiresAt:    claims.ExpiresAt,
	}, nil
}

// Authenticate verifies the token and checks revocation.
func (s *Service) Authenticate(ctx context.Context, token string) (TokenClaims, error) {
	claims, err := s.tokens.Verify(ctx, token)
	if err != nil {
		return TokenClaims{}, ErrUnauthorized
	}

	if !claims.ExpiresAt.IsZero() && s.clock.Now().After(claims.ExpiresAt) {
		return TokenClaims{}, ErrUnauthorized
	}

	if s.blacklist != nil && strings.TrimSpace(claims.TokenID) != "" {
		revoked, err := s.blacklist.IsRevoked(ctx, claims.TokenID)
		if err != nil {
			return TokenClaims{}, err
		}
		if revoked {
			return TokenClaims{}, ErrTokenRevoked
		}
	}

	// Global revocation via token_version in users table.
	user, err := s.users.GetByID(ctx, claims.UserID)
	if err != nil {
		return TokenClaims{}, ErrUnauthorized
	}
	if user.TokenVersion != claims.TokenVersion {
		return TokenClaims{}, ErrUnauthorized
	}

	return claims, nil
}

func (s *Service) Logout(ctx context.Context, token string) error {
	claims, err := s.tokens.Verify(ctx, token)
	if err != nil {
		return ErrUnauthorized
	}

	// Invalidate all tokens for this user going forward.
	if err := s.users.IncrementTokenVersion(ctx, claims.UserID); err != nil {
		return err
	}

	// Drop persisted refresh tokens for this user (stateful sessions).
	if s.refreshTokens != nil {
		if err := s.refreshTokens.DeleteByUser(ctx, claims.UserID); err != nil {
			return err
		}
	}

	// Best-effort revoke of current access token.
	if s.blacklist != nil && strings.TrimSpace(claims.TokenID) != "" {
		_ = s.blacklist.Revoke(ctx, claims.TokenID, claims.ExpiresAt)
	}

	return nil
}

func hashToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}
