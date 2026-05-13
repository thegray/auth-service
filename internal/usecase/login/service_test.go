package login

import (
	"context"
	"errors"
	"testing"
	"time"

	"auth-service/internal/auth"
	"auth-service/internal/shared"
	applogger "auth-service/pkg/logger"
)

type fakeVerifier struct {
	subject string
	profile shared.ExternalProfile
	err     error
}

func (f fakeVerifier) Verify(ctx context.Context, tokenProvider shared.Provider, appID string, idToken string) (string, shared.ExternalProfile, error) {
	return f.subject, f.profile, f.err
}

type fakeUsers struct {
	user *auth.User
	err  error
}

func (f *fakeUsers) UpsertByProvider(ctx context.Context, provider shared.Provider, subject string, profile shared.ExternalProfile) (*auth.User, error) {
	if f.err != nil {
		return nil, f.err
	}
	if f.user == nil {
		f.user = &auth.User{ID: 1, Provider: provider, ProviderSubject: subject, Email: profile.Email, Name: profile.Name, PictureURL: profile.PictureURL, TokenVersion: 1}
	}
	return f.user, nil
}

type fakeTokens struct {
	issued auth.TokenClaims
	token  string
	err    error
}

func (f *fakeTokens) Issue(ctx context.Context, claims auth.TokenClaims) (string, error) {
	if f.err != nil {
		return "", f.err
	}
	f.issued = claims
	if f.token == "" {
		f.token = "t1"
	}
	return f.token, nil
}

type fakeRefreshStore struct {
	created map[int64][]string
}

func (f *fakeRefreshStore) Create(ctx context.Context, userID int64, tokenHash string, expiresAt time.Time) error {
	if f.created == nil {
		f.created = map[int64][]string{}
	}
	f.created[userID] = append(f.created[userID], tokenHash)
	return nil
}

type fakeRefreshIssuer struct {
	issued map[string]auth.RefreshTokenClaims
	kid    string
}

func (f *fakeRefreshIssuer) KeyID() string { return f.kid }

func (f *fakeRefreshIssuer) Issue(ctx context.Context, claims auth.RefreshTokenClaims) (string, error) {
	if f.issued == nil {
		f.issued = map[string]auth.RefreshTokenClaims{}
	}
	token := "rt:" + claims.ID
	f.issued[token] = claims
	return token, nil
}

func (f *fakeRefreshIssuer) Verify(ctx context.Context, token string) (auth.RefreshTokenClaims, error) {
	claims, ok := f.issued[token]
	if !ok {
		return auth.RefreshTokenClaims{}, errors.New("bad token")
	}
	return claims, nil
}

type fakeClock struct{}

func (fakeClock) Now() time.Time { return time.Now() }

func TestLoginWithGoogle_Success(t *testing.T) {
	ctx := context.Background()
	svc := NewService(
		fakeVerifier{subject: "sub-1", profile: shared.ExternalProfile{Email: "a@b.com", Name: "A"}},
		&fakeUsers{},
		&fakeRefreshStore{},
		&fakeTokens{},
		&fakeRefreshIssuer{},
		fakeClock{},
		5*time.Minute, 24*time.Hour,
		applogger.Wrap(nil),
	)

	res, err := svc.LoginWithGoogle(ctx, "google", "id-token")
	if err != nil {
		t.Fatalf("LoginWithGoogle err = %v", err)
	}
	if res.AccessToken == "" || res.RefreshToken == "" || res.User == nil {
		t.Fatalf("result incomplete: %+v", res)
	}
	if res.User.ID == 0 {
		t.Fatalf("user ID not set")
	}
}

func TestLoginWithGoogle_InvalidCredential(t *testing.T) {
	svc := NewService(
		fakeVerifier{err: errors.New("nope")},
		&fakeUsers{},
		&fakeRefreshStore{},
		&fakeTokens{},
		&fakeRefreshIssuer{},
		fakeClock{},
		time.Minute, time.Hour,
		applogger.Wrap(nil),
	)
	_, err := svc.LoginWithGoogle(context.Background(), "", "bad-token")
	if !errors.Is(err, auth.ErrInvalidCredential) {
		t.Fatalf("err = %v, want ErrInvalidCredential", err)
	}
}

func TestLoginWithGoogle_EmptyToken(t *testing.T) {
	svc := NewService(
		fakeVerifier{},
		&fakeUsers{},
		&fakeRefreshStore{},
		&fakeTokens{},
		&fakeRefreshIssuer{},
		fakeClock{},
		time.Minute, time.Hour,
		applogger.Wrap(nil),
	)
	_, err := svc.LoginWithGoogle(context.Background(), "", "")
	if !errors.Is(err, auth.ErrInvalidCredential) {
		t.Fatalf("err = %v, want ErrInvalidCredential", err)
	}
}
