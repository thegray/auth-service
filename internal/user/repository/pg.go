package repository

import (
	"context"
	"errors"
	"strings"

	"auth-service/internal/user"
	applogger "auth-service/pkg/logger"

	"go.uber.org/zap"
	"gorm.io/gorm"
)

type Repository struct {
	db     *gorm.DB
	logger *applogger.Logger
}

func New(db *gorm.DB, logger *applogger.Logger) *Repository {
	if logger == nil {
		logger = applogger.Wrap(zap.NewNop())
	}
	return &Repository{db: db, logger: logger}
}

func (r *Repository) Create(ctx context.Context, account *user.User) error {
	log := r.logger
	log.InfoCtx(ctx, "persist user", zap.String("user_id", account.ID), zap.String("email", account.Email))

	model := fromDomain(account)
	if err := r.db.WithContext(ctx).Create(&model).Error; err != nil {
		log.ErrorCtx(ctx, "persist user failed", zap.String("user_id", account.ID), zap.Error(err))
		return err
	}

	log.InfoCtx(ctx, "persist user succeeded", zap.String("user_id", account.ID))
	return nil
}

func (r *Repository) GetByID(ctx context.Context, id string) (*user.User, error) {
	log := r.logger
	log.InfoCtx(ctx, "load user by id", zap.String("user_id", id))

	var model pgUser
	err := r.db.WithContext(ctx).First(&model, "id = ?", id).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			log.WarnCtx(ctx, "load user by id not found", zap.String("user_id", id))
			return nil, user.ErrNotFound
		}
		log.ErrorCtx(ctx, "load user by id failed", zap.String("user_id", id), zap.Error(err))
		return nil, err
	}
	log.InfoCtx(ctx, "load user by id succeeded", zap.String("user_id", id))
	return model.toDomain(), nil
}

func (r *Repository) GetByEmail(ctx context.Context, email string) (*user.User, error) {
	log := r.logger
	log.InfoCtx(ctx, "load user by email", zap.String("email", email))

	var model pgUser
	err := r.db.WithContext(ctx).First(&model, "lower(email) = lower(?)", strings.TrimSpace(email)).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			log.WarnCtx(ctx, "load user by email not found", zap.String("email", email))
			return nil, user.ErrNotFound
		}
		log.ErrorCtx(ctx, "load user by email failed", zap.String("email", email), zap.Error(err))
		return nil, err
	}
	log.InfoCtx(ctx, "load user by email succeeded", zap.String("email", email), zap.String("user_id", model.ID))
	return model.toDomain(), nil
}
