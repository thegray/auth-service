package repository

import (
	"time"

	"auth-service/internal/auth"
	"auth-service/internal/shared"
)

type pgUser struct {
	ID           int64   `gorm:"column:id;primaryKey;type:bigint"`
	Email        string  `gorm:"column:email;unique;not null"`
	DisplayName  *string `gorm:"column:display_name"`
	PasswordHash *string `gorm:"column:password_hash"`
	TokenVersion int     `gorm:"column:token_version;not null;default:1"`
	CreatedAt    int64   `gorm:"column:created_at;not null"`
	UpdatedAt    int64   `gorm:"column:updated_at;not null"`
}

func (pgUser) TableName() string { return "users" }

type pgIdentity struct {
	ID             int64   `gorm:"column:id;primaryKey;type:bigint"`
	UserID         int64   `gorm:"column:user_id;not null;index"`
	Provider       string  `gorm:"column:provider;not null;index:idx_provider_user_id,unique"`
	ProviderUserID string  `gorm:"column:provider_user_id;not null;index:idx_provider_user_id,unique"`
	ProviderEmail  *string `gorm:"column:provider_email"`
	LastLoginAt    *int64  `gorm:"column:last_login_at"`
}

func (pgIdentity) TableName() string { return "identities" }

type pgRefreshToken struct {
	ID        int64  `gorm:"column:id;primaryKey;type:bigint"`
	UserID    int64  `gorm:"column:user_id;not null;index"`
	TokenHash string `gorm:"column:token_hash;not null"`
	ExpiresAt int64  `gorm:"column:expires_at;not null"`
	CreatedAt int64  `gorm:"column:created_at;not null"`
}

func (pgRefreshToken) TableName() string { return "refresh_tokens" }

func (u pgUser) toDomain(provider shared.Provider, providerSubject string, profile shared.ExternalProfile) *auth.User {
	created := time.UnixMilli(u.CreatedAt).UTC()
	updated := time.UnixMilli(u.UpdatedAt).UTC()
	name := profile.Name
	if u.DisplayName != nil && *u.DisplayName != "" {
		name = *u.DisplayName
	}
	return &auth.User{
		ID:              u.ID,
		Provider:        provider,
		ProviderSubject: providerSubject,
		Email:           u.Email,
		Name:            name,
		PictureURL:      profile.PictureURL,
		TokenVersion:    u.TokenVersion,
		CreatedAt:       created,
		UpdatedAt:       updated,
	}
}

func (u pgUser) toDomainBare() *auth.User {
	created := time.UnixMilli(u.CreatedAt).UTC()
	updated := time.UnixMilli(u.UpdatedAt).UTC()
	name := ""
	if u.DisplayName != nil {
		name = *u.DisplayName
	}
	return &auth.User{
		ID:           u.ID,
		Email:        u.Email,
		Name:         name,
		TokenVersion: u.TokenVersion,
		CreatedAt:    created,
		UpdatedAt:    updated,
	}
}
