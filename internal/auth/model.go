package auth

import (
	"auth-service/internal/shared"
	"time"
)

type User struct {
	ID              int64
	Provider        shared.Provider
	ProviderSubject string
	Email           string
	Name            string
	PictureURL      string
	TokenVersion    int
	CreatedAt       time.Time
	UpdatedAt       time.Time
}

type TokenClaims struct {
	TokenID         string
	UserID          int64
	Email           string
	IssuedAt        time.Time
	ExpiresAt       time.Time
	Provider        shared.Provider
	ProviderSubject string
}

type RefreshTokenClaims struct {
	ID        string    `json:"jti"` // Unique Token ID
	Subject   string    `json:"sub"` // User ID
	Version   int       `json:"v"`   // Current token_version
	Type      string    `json:"typ"` // Always "refresh"
	IssuedAt  time.Time `json:"iat"`
	ExpiresAt time.Time `json:"exp"`
}

type LoginResult struct {
	AccessToken  string
	RefreshToken string
	User         *User
	ExpiresAt    time.Time
}
