package token

import (
	"context"

	"auth-service/internal/shared"
)

type IDTokenVerifier interface {
	Verify(ctx context.Context, tokenProvider shared.Provider, appID string, idToken string) (subject string, profile shared.ExternalProfile, err error)
}

type ClientIDProvider interface {
	GetClientID(ctx context.Context, id string, provider string) (string, error)
}
