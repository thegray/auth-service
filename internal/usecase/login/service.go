package login

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	"auth-service/internal/auth"
	"auth-service/internal/shared"
	applogger "auth-service/pkg/logger"

	"github.com/google/uuid"
	"go.uber.org/zap"
)

const (
	defaultAccessTTL  = 15 * time.Minute
	defaultRefreshTTL = 1 * 24 * time.Hour
)

type Service struct {
	verifier      IDTokenVerifier
	users         UserRepository
	refreshTokens RefreshTokenStore
	tokens        TokenIssuer
	refreshIssuer RefreshTokenIssuer
	clock         Clock
	ttl           time.Duration
	refreshTTL    time.Duration
	log           *applogger.Logger
}

func NewService(verifier IDTokenVerifier, users UserRepository, refreshTokens RefreshTokenStore, tokens TokenIssuer, refreshIssuer RefreshTokenIssuer, clock Clock, ttl, refreshTTL time.Duration, log *applogger.Logger) *Service {
	if ttl <= 0 {
		ttl = defaultAccessTTL
	}
	if refreshTTL <= 0 {
		refreshTTL = defaultRefreshTTL
	}
	return &Service{
		verifier:      verifier,
		users:         users,
		refreshTokens: refreshTokens,
		tokens:        tokens,
		refreshIssuer: refreshIssuer,
		clock:         clock,
		ttl:           ttl,
		refreshTTL:    refreshTTL,
		log:           log.Named("login-svc"),
	}
}

func (s *Service) LoginWithGoogle(ctx context.Context, appID string, idToken string) (auth.LoginResult, error) {
	if strings.TrimSpace(idToken) == "" {
		return auth.LoginResult{}, auth.ErrInvalidCredential
	}

	if s.verifier == nil {
		return auth.LoginResult{}, auth.ErrInvalidCredential
	}

	subject, profile, err := s.verifier.Verify(ctx, shared.ProviderGoogle, appID, idToken)
	if err != nil || strings.TrimSpace(subject) == "" {
		s.log.ErrorCtx(ctx, "token verification failed", zap.String("provider", shared.ProviderGoogle.String()), zap.Error(err))
		return auth.LoginResult{}, auth.ErrInvalidCredential
	}

	now := s.clock.Now().UTC()
	user, err := s.users.UpsertByProvider(ctx, shared.ProviderGoogle, subject, profile)
	if err != nil {
		s.log.ErrorCtx(ctx, "failed to upsert user", zap.String("provider", shared.ProviderGoogle.String()), zap.Error(err))
		return auth.LoginResult{}, err
	}

	claims := auth.TokenClaims{
		TokenID:         uuid.NewString(),
		UserID:          user.ID,
		Email:           user.Email,
		IssuedAt:        now,
		ExpiresAt:       now.Add(s.ttl),
		Provider:        shared.ProviderGoogle,
		ProviderSubject: subject,
	}

	token, err := s.tokens.Issue(ctx, claims)
	if err != nil {
		s.log.ErrorCtx(ctx, "failed to issue access token", zap.Error(err))
		return auth.LoginResult{}, err
	}

	refreshToken := ""
	var refreshClaims auth.RefreshTokenClaims
	if s.refreshTokens != nil && s.refreshIssuer != nil {
		refreshClaims = auth.RefreshTokenClaims{
			ID:        uuid.NewString(),
			Subject:   fmt.Sprintf("%d", user.ID),
			Version:   user.TokenVersion,
			Type:      "refresh",
			IssuedAt:  now,
			ExpiresAt: now.Add(s.refreshTTL),
		}

		issued, err := s.refreshIssuer.Issue(ctx, refreshClaims)
		if err != nil {
			s.log.ErrorCtx(ctx, "failed to issue refresh token", zap.Int64("user_id", user.ID), zap.Error(err))
			return auth.LoginResult{}, err
		}
		refreshToken = issued

		refreshHash := hashToken(refreshToken)
		if err := s.refreshTokens.Create(ctx, user.ID, refreshHash, refreshClaims.ExpiresAt); err != nil {
			s.log.ErrorCtx(ctx, "failed to persist refresh token", zap.Int64("user_id", user.ID), zap.Error(err))
			return auth.LoginResult{}, err
		}
	}

	refreshExpiresAt := time.Time{}
	if refreshToken != "" {
		refreshExpiresAt = refreshClaims.ExpiresAt
	}
	return auth.LoginResult{
		AccessToken:      token,
		RefreshToken:     refreshToken,
		User:             user,
		ExpiresAt:        claims.ExpiresAt,
		RefreshExpiresAt: refreshExpiresAt,
	}, nil
}

func hashToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}
