package auth

import "time"

type Provider string

const (
	ProviderGoogle Provider = "google"
)

type User struct {
	ID              int64
	Provider        Provider
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
	TokenVersion    int
	IssuedAt        time.Time
	ExpiresAt       time.Time
	Provider        Provider
	ProviderSubject string
}

type LoginResult struct {
	AccessToken  string
	RefreshToken string
	User         *User
	ExpiresAt    time.Time
}
