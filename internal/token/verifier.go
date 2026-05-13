package token

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"auth-service/internal/shared"

	"google.golang.org/api/idtoken"
)

const (
	claimEmail         = "email"
	claimName          = "name"
	claimPicture       = "picture"
	claimEmailVerified = "email_verified"
)

var (
	ErrInvalidIDToken      = errors.New("invalid id token")
	ErrUnsupportedProvider = errors.New("unsupported token provider")
)

// Verifier validates ID tokens and extracts the subject + basic profile.
type Verifier struct {
	provider ClientIDProvider
}

func NewVerifier(provider ClientIDProvider) *Verifier {
	return &Verifier{provider: provider}
}

func (v *Verifier) Verify(ctx context.Context, tokenProvider shared.Provider, appID string, credential string) (string, shared.ExternalProfile, error) {
	switch tokenProvider {
	case shared.ProviderGoogle:
		return v.verifyGoogle(ctx, appID, credential)
	default:
		return "", shared.ExternalProfile{}, ErrUnsupportedProvider
	}
}

func (v *Verifier) verifyGoogle(ctx context.Context, appID string, credential string) (string, shared.ExternalProfile, error) {
	audience, err := v.provider.GetClientID(ctx, appID, shared.ProviderGoogle.String())
	if err != nil || strings.TrimSpace(audience) == "" {
		return "", shared.ExternalProfile{}, fmt.Errorf("%w: missing audience", ErrInvalidIDToken)
	}
	if strings.TrimSpace(credential) == "" {
		return "", shared.ExternalProfile{}, ErrInvalidIDToken
	}

	payload, err := idtoken.Validate(ctx, credential, audience)
	if err != nil {
		return "", shared.ExternalProfile{}, ErrInvalidIDToken
	}
	if strings.TrimSpace(payload.Subject) == "" {
		return "", shared.ExternalProfile{}, ErrInvalidIDToken
	}

	email, _ := payload.Claims[claimEmail].(string)
	email = strings.TrimSpace(email)
	if email == "" {
		return "", shared.ExternalProfile{}, ErrInvalidIDToken
	}

	if verified, ok := payload.Claims[claimEmailVerified].(bool); ok && !verified {
		return "", shared.ExternalProfile{}, ErrInvalidIDToken
	}

	name, _ := payload.Claims[claimName].(string)
	picture, _ := payload.Claims[claimPicture].(string)

	return payload.Subject, shared.ExternalProfile{
		Email:      email,
		Name:       strings.TrimSpace(name),
		PictureURL: strings.TrimSpace(picture),
	}, nil
}

var _ IDTokenVerifier = (*Verifier)(nil)
