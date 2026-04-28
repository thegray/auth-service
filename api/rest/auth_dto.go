package rest

import "time"

type googleLoginRequest struct {
	IDToken string `json:"id_token"`
}

type googleLoginResponse struct {
	TokenType    string           `json:"token_type"`
	AccessToken  string           `json:"access_token"`
	RefreshToken string           `json:"refresh_token"`
	ExpiresAt    time.Time        `json:"expires_at"`
	User         authUserResponse `json:"user"`
}

type authUserResponse struct {
	ID          int64  `json:"id"`
	Email       string `json:"email"`
	DisplayName string `json:"display_name"`
}

type refreshRequest struct {
	RefreshToken string `json:"refresh_token"`
}

type refreshResponse struct {
	TokenType    string           `json:"token_type"`
	AccessToken  string           `json:"access_token"`
	RefreshToken string           `json:"refresh_token"`
	ExpiresAt    time.Time        `json:"expires_at"`
	User         authUserResponse `json:"user"`
}
