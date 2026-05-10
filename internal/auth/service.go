package auth

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
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
	defaultRefreshTTL = 1 * 24 * time.Hour
)

type Service struct {
	users          UserRepository
	refreshTokens  RefreshTokenRepository
	googleVerifier GoogleIDTokenVerifier
	tokens         TokenIssuer
	refreshIssuer  RefreshTokenIssuer
	blacklist      BlacklistStore
	clock          Clock
	ttl            time.Duration
	refreshTTL     time.Duration
}

type ServiceClock struct{}

func (ServiceClock) Now() time.Time { return time.Now() }

func NewService(users UserRepository, refreshTokens RefreshTokenRepository, googleVerifier GoogleIDTokenVerifier, tokens TokenIssuer, refreshIssuer RefreshTokenIssuer, blacklist BlacklistStore, clock Clock, ttl, refreshTTL time.Duration) *Service {
	if ttl <= 0 {
		ttl = defaultAccessTTL
	}
	if refreshTTL <= 0 {
		refreshTTL = defaultRefreshTTL
	}

	return &Service{
		users:          users,
		refreshTokens:  refreshTokens,
		googleVerifier: googleVerifier,
		tokens:         tokens,
		refreshIssuer:  refreshIssuer,
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
		IssuedAt:        now,
		ExpiresAt:       now.Add(s.ttl),
		Provider:        ProviderGoogle,
		ProviderSubject: subject,
	}

	token, err := s.tokens.Issue(ctx, claims)
	if err != nil {
		return LoginResult{}, err
	}

	refreshToken := ""
	if s.refreshTokens != nil && s.refreshIssuer != nil {
		refreshClaims := RefreshTokenClaims{
			ID:        uuid.NewString(),
			Subject:   fmt.Sprintf("%d", user.ID),
			Version:   user.TokenVersion,
			Type:      "refresh",
			IssuedAt:  now,
			ExpiresAt: now.Add(s.refreshTTL),
		}

		issued, err := s.refreshIssuer.Issue(ctx, refreshClaims)
		if err != nil {
			return LoginResult{}, err
		}
		refreshToken = issued

		refreshHash := hashToken(refreshToken)
		if err := s.refreshTokens.Create(ctx, user.ID, refreshHash, refreshClaims.ExpiresAt); err != nil {
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

	return claims, nil
}

func (s *Service) Logout(ctx context.Context, token string) error {
	token = strings.TrimSpace(token)
	if token == "" {
		return ErrUnauthorized
	}

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

	if s.blacklist != nil && strings.TrimSpace(claims.TokenID) != "" {
		if err := s.blacklist.Revoke(ctx, claims.TokenID, claims.ExpiresAt); err != nil {
			return err
		}
	}

	return nil
}

func hashToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

// Refresh exchanges a valid refresh token for a new access token and a rotated refresh token.
func (s *Service) Refresh(ctx context.Context, refreshToken string) (LoginResult, error) {
	if s.refreshTokens == nil || s.refreshIssuer == nil {
		return LoginResult{}, ErrUnauthorized
	}
	refreshToken = strings.TrimSpace(refreshToken)
	if refreshToken == "" {
		return LoginResult{}, ErrUnauthorized
	}

	now := s.clock.Now().UTC()
	refreshClaims, err := s.refreshIssuer.Verify(ctx, refreshToken)
	if err != nil {
		return LoginResult{}, ErrUnauthorized
	}
	if !refreshClaims.ExpiresAt.IsZero() && now.After(refreshClaims.ExpiresAt) {
		return LoginResult{}, ErrUnauthorized
	}

	userID, err := strconv.ParseInt(strings.TrimSpace(refreshClaims.Subject), 10, 64)
	if err != nil || userID <= 0 {
		return LoginResult{}, ErrUnauthorized
	}

	oldHash := hashToken(refreshToken)
	dbUserID, expiresAt, err := s.refreshTokens.GetByHash(ctx, oldHash)
	if err != nil || dbUserID != userID {
		return LoginResult{}, ErrUnauthorized
	}
	if !expiresAt.IsZero() && now.After(expiresAt) {
		_ = s.refreshTokens.DeleteByHash(ctx, oldHash)
		return LoginResult{}, ErrUnauthorized
	}

	user, err := s.users.GetByID(ctx, userID)
	if err != nil {
		return LoginResult{}, ErrUnauthorized
	}

	// token_version check happens on refresh token, not access token.
	if refreshClaims.Version != user.TokenVersion {
		_ = s.refreshTokens.DeleteByHash(ctx, oldHash)
		return LoginResult{}, ErrUnauthorized
	}

	claims := TokenClaims{
		TokenID:   uuid.NewString(),
		UserID:    user.ID,
		Email:     user.Email,
		IssuedAt:  now,
		ExpiresAt: now.Add(s.ttl),
	}

	accessToken, err := s.tokens.Issue(ctx, claims)
	if err != nil {
		return LoginResult{}, err
	}

	// Rotate refresh token: delete old hash and insert new token.
	newRefreshClaims := RefreshTokenClaims{
		ID:        uuid.NewString(),
		Subject:   fmt.Sprintf("%d", user.ID),
		Version:   user.TokenVersion,
		Type:      "refresh",
		IssuedAt:  now,
		ExpiresAt: now.Add(s.refreshTTL),
	}
	newRefreshToken, err := s.refreshIssuer.Issue(ctx, newRefreshClaims)
	if err != nil {
		return LoginResult{}, err
	}
	newHash := hashToken(newRefreshToken)

	if err := s.refreshTokens.DeleteByHash(ctx, oldHash); err != nil {
		return LoginResult{}, err
	}
	if err := s.refreshTokens.Create(ctx, user.ID, newHash, newRefreshClaims.ExpiresAt); err != nil {
		return LoginResult{}, err
	}

	return LoginResult{
		AccessToken:  accessToken,
		RefreshToken: newRefreshToken,
		User:         user,
		ExpiresAt:    claims.ExpiresAt,
	}, nil
}
