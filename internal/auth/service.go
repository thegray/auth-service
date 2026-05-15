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

	applogger "auth-service/pkg/logger"

	"github.com/google/uuid"
	"go.uber.org/zap"
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
	users         UserRepository
	refreshTokens RefreshTokenRepository
	tokens        TokenIssuer
	refreshIssuer RefreshTokenIssuer
	blacklist     BlacklistStore
	clock         Clock
	ttl           time.Duration
	refreshTTL    time.Duration
	log           *applogger.Logger
}

type ServiceClock struct{}

func (ServiceClock) Now() time.Time { return time.Now() }

func NewService(users UserRepository, refreshTokens RefreshTokenRepository, tokens TokenIssuer, refreshIssuer RefreshTokenIssuer, blacklist BlacklistStore, clock Clock, ttl, refreshTTL time.Duration, log *applogger.Logger) *Service {
	if ttl <= 0 {
		ttl = defaultAccessTTL
	}
	if refreshTTL <= 0 {
		refreshTTL = defaultRefreshTTL
	}

	return &Service{
		users:         users,
		refreshTokens: refreshTokens,
		tokens:        tokens,
		refreshIssuer: refreshIssuer,
		blacklist:     blacklist,
		clock:         clock,
		ttl:           ttl,
		refreshTTL:    refreshTTL,
		log:           log.Named("auth-svc"),
	}
}

// Authenticate verifies the token and checks revocation.
func (s *Service) Authenticate(ctx context.Context, token string) (TokenClaims, error) {
	claims, err := s.tokens.Verify(ctx, token)
	if err != nil {
		s.log.WarnCtx(ctx, "token verification failed", zap.Error(err))
		return TokenClaims{}, ErrUnauthorized
	}

	if !claims.ExpiresAt.IsZero() && s.clock.Now().After(claims.ExpiresAt) {
		s.log.WarnCtx(ctx, "token expired", zap.String("jti", claims.TokenID), zap.Time("expires_at", claims.ExpiresAt))
		return TokenClaims{}, ErrUnauthorized
	}

	if s.blacklist != nil && strings.TrimSpace(claims.TokenID) != "" {
		revoked, err := s.blacklist.IsRevoked(ctx, claims.TokenID)
		if err != nil {
			s.log.ErrorCtx(ctx, "failed to check blacklist", zap.String("jti", claims.TokenID), zap.Error(err))
			return TokenClaims{}, err
		}
		if revoked {
			s.log.WarnCtx(ctx, "token revoked", zap.String("jti", claims.TokenID))
			return TokenClaims{}, ErrTokenRevoked
		}
	}

	return claims, nil
}

func (s *Service) Logout(ctx context.Context, accessToken string, refreshToken string) error {
	accessToken = strings.TrimSpace(accessToken)
	if accessToken == "" {
		return ErrUnauthorized
	}

	claims, err := s.tokens.Verify(ctx, accessToken)
	if err != nil {
		s.log.WarnCtx(ctx, "logout attempt with invalid token", zap.Error(err))
		return ErrUnauthorized
	}

	// Invalidate all tokens for this user going forward.
	if err := s.users.IncrementTokenVersion(ctx, claims.UserID); err != nil {
		s.log.ErrorCtx(ctx, "failed to increment token version during logout", zap.Int64("user_id", claims.UserID), zap.Error(err))
		return err
	}

	// Delete the specific refresh token paired with this session.
	if s.refreshTokens != nil && refreshToken != "" {
		hash := hashToken(refreshToken)
		if err := s.refreshTokens.DeleteByHash(ctx, hash); err != nil {
			s.log.ErrorCtx(ctx, "failed to delete refresh token during logout", zap.Int64("user_id", claims.UserID), zap.Error(err))
			return err
		}
	}

	if s.blacklist != nil && strings.TrimSpace(claims.TokenID) != "" {
		if err := s.blacklist.Revoke(ctx, claims.TokenID, claims.ExpiresAt); err != nil {
			s.log.ErrorCtx(ctx, "failed to blacklist token during logout", zap.String("jti", claims.TokenID), zap.Error(err))
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
		s.log.WarnCtx(ctx, "refresh token verification failed", zap.Error(err))
		return LoginResult{}, ErrUnauthorized
	}
	if !refreshClaims.ExpiresAt.IsZero() && now.After(refreshClaims.ExpiresAt) {
		s.log.WarnCtx(ctx, "refresh token expired", zap.String("jti", refreshClaims.ID))
		return LoginResult{}, ErrUnauthorized
	}

	userID, err := strconv.ParseInt(strings.TrimSpace(refreshClaims.Subject), 10, 64)
	if err != nil || userID <= 0 {
		s.log.ErrorCtx(ctx, "failed to parse userID from refresh token subject", zap.String("sub", refreshClaims.Subject), zap.Error(err))
		return LoginResult{}, ErrUnauthorized
	}

	oldHash := hashToken(refreshToken)
	dbUserID, expiresAt, err := s.refreshTokens.GetByHash(ctx, oldHash)
	if err != nil || dbUserID != userID {
		s.log.WarnCtx(ctx, "refresh token not found or userID mismatch", zap.Int64("token_user_id", userID), zap.Int64("db_user_id", dbUserID), zap.Error(err))
		return LoginResult{}, ErrUnauthorized
	}
	if !expiresAt.IsZero() && now.After(expiresAt) {
		err := s.refreshTokens.DeleteByHash(ctx, oldHash)
		if err != nil {
			s.log.ErrorCtx(ctx, "fail delete refresh token", zap.Int64("token_user_id", userID), zap.Int64("db_user_id", dbUserID), zap.Error(err))
		}
		return LoginResult{}, ErrUnauthorized
	}

	user, err := s.users.GetByID(ctx, userID)
	if err != nil {
		s.log.ErrorCtx(ctx, "failed to get user during refresh", zap.Int64("user_id", userID), zap.Error(err))
		return LoginResult{}, ErrUnauthorized
	}

	// token_version check happens on refresh token, not access token.
	if refreshClaims.Version != user.TokenVersion {
		_ = s.refreshTokens.DeleteByHash(ctx, oldHash)
		s.log.WarnCtx(ctx, "refresh token version mismatch", zap.Int64("user_id", userID), zap.Int("token_v", refreshClaims.Version), zap.Int("db_v", user.TokenVersion))
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
		s.log.ErrorCtx(ctx, "failed to issue access token during refresh", zap.Int64("user_id", userID), zap.Error(err))
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
		s.log.ErrorCtx(ctx, "failed to issue new refresh token during rotation", zap.Int64("user_id", userID), zap.Error(err))
		return LoginResult{}, err
	}
	newHash := hashToken(newRefreshToken)

	// TODO: wrap in tx?
	if err := s.refreshTokens.DeleteByHash(ctx, oldHash); err != nil {
		s.log.ErrorCtx(ctx, "failed to delete old refresh token hash", zap.Error(err))
		return LoginResult{}, err
	}
	if err := s.refreshTokens.Create(ctx, user.ID, newHash, newRefreshClaims.ExpiresAt); err != nil {
		s.log.ErrorCtx(ctx, "failed to create new refresh token hash", zap.Int64("user_id", userID), zap.Error(err))
		return LoginResult{}, err
	}

	return LoginResult{
		AccessToken:      accessToken,
		RefreshToken:     newRefreshToken,
		User:             user,
		ExpiresAt:        claims.ExpiresAt,
		RefreshExpiresAt: newRefreshClaims.ExpiresAt,
	}, nil
}
