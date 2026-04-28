package repository

import (
	"context"
	"errors"
	"strings"
	"time"

	"auth-service/internal/auth"
	"auth-service/pkg/idgenerator"
	applogger "auth-service/pkg/logger"

	"go.uber.org/zap"
	"gorm.io/gorm"
)

type PostgresRepository struct {
	db    *gorm.DB
	log   *applogger.Logger
	ids   *idgenerator.Generator
	clock func() time.Time
}

func NewPostgres(db *gorm.DB, log *applogger.Logger, machineID int64) *PostgresRepository {
	if log == nil {
		log = applogger.Wrap(zap.NewNop())
	}
	return &PostgresRepository{
		db:    db,
		log:   log,
		ids:   idgenerator.New(machineID),
		clock: time.Now,
	}
}

func (r *PostgresRepository) UpsertByProvider(ctx context.Context, provider auth.Provider, subject string, profile auth.ExternalProfile) (*auth.User, error) {
	subject = strings.TrimSpace(subject)
	if subject == "" {
		return nil, errors.New("subject is required")
	}

	email := strings.TrimSpace(profile.Email)
	displayName := strings.TrimSpace(profile.Name)
	nowMs := r.clock().UTC().UnixMilli()

	var out *auth.User
	err := r.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		var ident pgIdentity
		err := tx.First(&ident, "provider = ? AND provider_user_id = ?", string(provider), subject).Error
		switch {
		case err == nil:
			// Update identity metadata.
			var providerEmail *string
			if email != "" {
				providerEmail = &email
			}
			lastLogin := nowMs
			if err := tx.Model(&pgIdentity{}).
				Where("id = ?", ident.ID).
				Updates(map[string]any{
					"provider_email": providerEmail,
					"last_login_at":  &lastLogin,
				}).Error; err != nil {
				return err
			}

			// Load user; keep email stable to avoid conflicts.
			var user pgUser
			if err := tx.First(&user, "id = ?", ident.UserID).Error; err != nil {
				return err
			}
			if displayName != "" {
				if err := tx.Model(&pgUser{}).
					Where("id = ?", user.ID).
					Updates(map[string]any{
						"display_name": &displayName,
						"updated_at":   nowMs,
					}).Error; err != nil {
					return err
				}
				user.DisplayName = &displayName
				user.UpdatedAt = nowMs
			}

			out = user.toDomain(provider, subject, profile)
			return nil

		case errors.Is(err, gorm.ErrRecordNotFound):
			// Try attach identity to an existing user by email; otherwise create a new user.
			var user pgUser
			uerr := tx.First(&user, "lower(email) = lower(?)", email).Error
			switch {
			case uerr == nil:
				// Update display name if provided.
				if displayName != "" {
					if err := tx.Model(&pgUser{}).
						Where("id = ?", user.ID).
						Updates(map[string]any{
							"display_name": &displayName,
							"updated_at":   nowMs,
						}).Error; err != nil {
						return err
					}
					user.DisplayName = &displayName
					user.UpdatedAt = nowMs
				}
			case errors.Is(uerr, gorm.ErrRecordNotFound):
				if email == "" {
					return errors.New("email is required")
				}

				var dn *string
				if displayName != "" {
					dn = &displayName
				}
				user = pgUser{
					ID:           r.ids.NewID(nowMs),
					Email:        email,
					DisplayName:  dn,
					PasswordHash: nil,
					TokenVersion: 1,
					CreatedAt:    nowMs,
					UpdatedAt:    nowMs,
				}
				if err := tx.Create(&user).Error; err != nil {
					return err
				}
			default:
				return uerr
			}

			// Create new identity.
			var providerEmail *string
			if email != "" {
				providerEmail = &email
			}
			lastLogin := nowMs
			ident = pgIdentity{
				ID:             r.ids.NewID(nowMs),
				UserID:         user.ID,
				Provider:       string(provider),
				ProviderUserID: subject,
				ProviderEmail:  providerEmail,
				LastLoginAt:    &lastLogin,
			}
			if err := tx.Create(&ident).Error; err != nil {
				return err
			}

			out = user.toDomain(provider, subject, profile)
			return nil

		default:
			return err
		}
	})
	if err != nil {
		r.log.ErrorCtx(ctx, "upsert identity failed", zap.String("provider", string(provider)), zap.Error(err))
		return nil, err
	}
	return out, nil
}

func (r *PostgresRepository) GetByID(ctx context.Context, id int64) (*auth.User, error) {
	var user pgUser
	if err := r.db.WithContext(ctx).First(&user, "id = ?", id).Error; err != nil {
		return nil, err
	}
	return user.toDomainBare(), nil
}

func (r *PostgresRepository) IncrementTokenVersion(ctx context.Context, userID int64) error {
	nowMs := r.clock().UTC().UnixMilli()
	return r.db.WithContext(ctx).
		Model(&pgUser{}).
		Where("id = ?", userID).
		Updates(map[string]any{
			"token_version": gorm.Expr("token_version + 1"),
			"updated_at":    nowMs,
		}).Error
}

func (r *PostgresRepository) Create(ctx context.Context, userID int64, tokenHash string, expiresAt time.Time) error {
	tokenHash = strings.TrimSpace(tokenHash)
	if tokenHash == "" {
		return errors.New("token_hash is required")
	}

	nowMs := r.clock().UTC().UnixMilli()
	row := pgRefreshToken{
		ID:        r.ids.NewID(nowMs),
		UserID:    userID,
		TokenHash: tokenHash,
		ExpiresAt: expiresAt.UTC().UnixMilli(),
		CreatedAt: nowMs,
	}
	return r.db.WithContext(ctx).Create(&row).Error
}

func (r *PostgresRepository) DeleteByUser(ctx context.Context, userID int64) error {
	return r.db.WithContext(ctx).Delete(&pgRefreshToken{}, "user_id = ?", userID).Error
}

var _ auth.UserRepository = (*PostgresRepository)(nil)
var _ auth.RefreshTokenRepository = (*PostgresRepository)(nil)
