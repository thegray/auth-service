package user

import (
	"context"
	"errors"
	"strings"

	applogger "auth-service/pkg/logger"

	"go.uber.org/zap"
)

var (
	ErrNotFound            = errors.New("user not found")
	ErrInvalidCredentials  = errors.New("invalid credentials")
	ErrInvalidLoginRequest = errors.New("email and password are required")
)

type Service struct {
	repo   Repository
	hasher PasswordHasher
	log    *applogger.Logger
}

func NewService(repo Repository, hasher PasswordHasher, logger *applogger.Logger) *Service {
	if logger == nil {
		logger = applogger.Wrap(zap.NewNop())
	}
	return &Service{repo: repo, hasher: hasher, log: logger}
}

func (s *Service) Login(ctx context.Context, input LoginInput) (*User, error) {
	log := s.log
	if strings.TrimSpace(input.Email) == "" || strings.TrimSpace(input.Password) == "" {
		log.WarnCtx(ctx, "invalid login request", zap.String("email", input.Email))
		return nil, ErrInvalidLoginRequest
	}

	log.InfoCtx(ctx, "login attempt", zap.String("email", input.Email))
	account, err := s.repo.GetByEmail(ctx, strings.ToLower(strings.TrimSpace(input.Email)))
	if err != nil {
		log.WarnCtx(ctx, "login failed: account lookup", zap.String("email", input.Email), zap.Error(err))
		return nil, ErrInvalidCredentials
	}

	if err := s.hasher.Compare(account.PasswordHash, input.Password); err != nil {
		log.WarnCtx(ctx, "login failed: invalid password", zap.String("user_id", account.ID), zap.Error(err))
		return nil, ErrInvalidCredentials
	}

	log.InfoCtx(ctx, "login succeeded", zap.String("user_id", account.ID))
	return account, nil
}

func (s *Service) GetByID(ctx context.Context, id string) (*User, error) {
	log := s.log
	log.InfoCtx(ctx, "fetch user", zap.String("user_id", id))
	account, err := s.repo.GetByID(ctx, id)
	if err != nil {
		log.WarnCtx(ctx, "fetch user failed", zap.String("user_id", id), zap.Error(err))
		return nil, err
	}

	log.InfoCtx(ctx, "fetch user succeeded", zap.String("user_id", id))
	return account, nil
}
