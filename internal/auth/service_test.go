package auth

import (
	"context"
	"errors"
	"testing"
	"time"
)

type fakeVerifier struct {
	subject string
	profile ExternalProfile
	err     error
}

func (f fakeVerifier) Verify(ctx context.Context, credential string) (string, ExternalProfile, error) {
	return f.subject, f.profile, f.err
}

type fakeUsers struct {
	user *User
	err  error
}

func (f *fakeUsers) UpsertByProvider(ctx context.Context, provider Provider, subject string, profile ExternalProfile) (*User, error) {
	if f.err != nil {
		return nil, f.err
	}
	if f.user == nil {
		f.user = &User{ID: 1, Provider: provider, ProviderSubject: subject, Email: profile.Email, Name: profile.Name, PictureURL: profile.PictureURL, TokenVersion: 1}
	}
	return f.user, nil
}

func (f *fakeUsers) GetByID(ctx context.Context, id int64) (*User, error) { return f.user, nil }

func (f *fakeUsers) IncrementTokenVersion(ctx context.Context, userID int64) error {
	if f.user != nil && f.user.ID == userID {
		f.user.TokenVersion++
	}
	return nil
}

type fakeTokens struct {
	issued TokenClaims
	token  string
	err    error
}

func (f *fakeTokens) Issue(ctx context.Context, claims TokenClaims) (string, error) {
	if f.err != nil {
		return "", f.err
	}
	f.issued = claims
	if f.token == "" {
		f.token = "t1"
	}
	return f.token, nil
}

func (f *fakeTokens) Verify(ctx context.Context, token string) (TokenClaims, error) {
	if f.err != nil {
		return TokenClaims{}, f.err
	}
	if token != f.token {
		return TokenClaims{}, errors.New("bad token")
	}
	return f.issued, nil
}

type fakeRefreshTokens struct {
	created map[int64][]string
}

func (f *fakeRefreshTokens) Create(ctx context.Context, userID int64, tokenHash string, expiresAt time.Time) error {
	if f.created == nil {
		f.created = map[int64][]string{}
	}
	f.created[userID] = append(f.created[userID], tokenHash)
	return nil
}

func (f *fakeRefreshTokens) DeleteByUser(ctx context.Context, userID int64) error {
	if f.created != nil {
		delete(f.created, userID)
	}
	return nil
}

type fakeBlacklist struct {
	revoked map[string]time.Time
}

func (f *fakeBlacklist) Revoke(ctx context.Context, tokenID string, expiresAt time.Time) error {
	if f.revoked == nil {
		f.revoked = map[string]time.Time{}
	}
	f.revoked[tokenID] = expiresAt
	return nil
}

func (f *fakeBlacklist) IsRevoked(ctx context.Context, tokenID string) (bool, error) {
	if f.revoked == nil {
		return false, nil
	}
	_, ok := f.revoked[tokenID]
	return ok, nil
}

func TestService_LoginLogoutAuthenticate(t *testing.T) {
	ctx := context.Background()

	users := &fakeUsers{}
	verifier := fakeVerifier{subject: "google-sub-1", profile: ExternalProfile{Email: "a@example.com", Name: "A"}}
	tokens := &fakeTokens{}
	refreshTokens := &fakeRefreshTokens{}
	blacklist := &fakeBlacklist{}

	svc := NewService(users, refreshTokens, verifier, tokens, blacklist, 5*time.Minute, 24*time.Hour)

	res, err := svc.LoginWithGoogle(ctx, "id-token")
	if err != nil {
		t.Fatalf("LoginWithGoogle err = %v", err)
	}
	if res.AccessToken == "" || res.RefreshToken == "" || res.User == nil || res.User.ID == 0 {
		t.Fatalf("LoginWithGoogle result is incomplete: %+v", res)
	}
	if tokens.issued.UserID != res.User.ID {
		t.Fatalf("issued claims UserID mismatch: got=%d want=%d", tokens.issued.UserID, res.User.ID)
	}

	claims, err := svc.Authenticate(ctx, res.AccessToken)
	if err != nil {
		t.Fatalf("Authenticate err = %v", err)
	}
	if claims.UserID != res.User.ID {
		t.Fatalf("Authenticate UserID mismatch: got=%q want=%q", claims.UserID, res.User.ID)
	}

	if err := svc.Logout(ctx, res.AccessToken); err != nil {
		t.Fatalf("Logout err = %v", err)
	}

	_, err = svc.Authenticate(ctx, res.AccessToken)
	if !(errors.Is(err, ErrUnauthorized) || errors.Is(err, ErrTokenRevoked)) {
		t.Fatalf("Authenticate after Logout err = %v, want ErrUnauthorized or ErrTokenRevoked", err)
	}
}

func TestService_Login_InvalidCredential(t *testing.T) {
	svc := NewService(&fakeUsers{}, &fakeRefreshTokens{}, fakeVerifier{err: errors.New("nope")}, &fakeTokens{}, &fakeBlacklist{}, time.Minute, time.Hour)
	_, err := svc.LoginWithGoogle(context.Background(), "token")
	if !errors.Is(err, ErrInvalidCredential) {
		t.Fatalf("err = %v, want ErrInvalidCredential", err)
	}
}
