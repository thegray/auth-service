package repository

import (
	"time"

	"auth-service/internal/user"
)

type pgUser struct {
	ID           string    `gorm:"column:id;primaryKey;type:text"`
	Email        string    `gorm:"column:email;not null;uniqueIndex"`
	PasswordHash string    `gorm:"column:password_hash;not null"`
	CreatedAt    time.Time `gorm:"column:created_at;autoCreateTime"`
}

func (pgUser) TableName() string {
	return "users"
}

func (p pgUser) toDomain() *user.User {
	return &user.User{
		ID:           p.ID,
		Email:        p.Email,
		PasswordHash: p.PasswordHash,
		CreatedAt:    p.CreatedAt,
	}
}

func fromDomain(u *user.User) pgUser {
	return pgUser{
		ID:           u.ID,
		Email:        u.Email,
		PasswordHash: u.PasswordHash,
		CreatedAt:    u.CreatedAt,
	}
}
