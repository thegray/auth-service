package repository

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"auth-service/internal/auth"

	"google.golang.org/api/idtoken"
)

const (
	claimEmail         = "email"
	claimName          = "name"
	claimPicture       = "picture"
	claimEmailVerified = "email_verified"
)

var ErrInvalidIDToken = errors.New("invalid google id token")

// GoogleVerifier validates Google ID tokens and extracts the subject + basic profile.
// It lives in this repository layer to match the structure concept (external integrations alongside DB/Redis).
type GoogleVerifier struct {
	audience string
}

func NewGoogleVerifier(audience string) *GoogleVerifier {
	return &GoogleVerifier{audience: strings.TrimSpace(audience)}
}

func (v *GoogleVerifier) Verify(ctx context.Context, credential string) (string, auth.ExternalProfile, error) {
	if strings.TrimSpace(v.audience) == "" {
		return "", auth.ExternalProfile{}, fmt.Errorf("%w: missing audience", ErrInvalidIDToken)
	}
	if strings.TrimSpace(credential) == "" {
		return "", auth.ExternalProfile{}, ErrInvalidIDToken
	}

	payload, err := idtoken.Validate(ctx, credential, v.audience)
	if err != nil {
		return "", auth.ExternalProfile{}, ErrInvalidIDToken
	}
	if strings.TrimSpace(payload.Subject) == "" {
		return "", auth.ExternalProfile{}, ErrInvalidIDToken
	}

	email, _ := payload.Claims[claimEmail].(string)
	email = strings.TrimSpace(email)
	if email == "" {
		return "", auth.ExternalProfile{}, ErrInvalidIDToken
	}

	// If present, enforce verified email.
	if verified, ok := payload.Claims[claimEmailVerified].(bool); ok && !verified {
		return "", auth.ExternalProfile{}, ErrInvalidIDToken
	}

	name, _ := payload.Claims[claimName].(string)
	picture, _ := payload.Claims[claimPicture].(string)

	return payload.Subject, auth.ExternalProfile{
		Email:      email,
		Name:       strings.TrimSpace(name),
		PictureURL: strings.TrimSpace(picture),
	}, nil
}

var _ auth.GoogleIDTokenVerifier = (*GoogleVerifier)(nil)
