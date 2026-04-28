package auth

import (
	"context"
	"errors"
	"strconv"
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
	byHash  map[string]struct {
		userID    int64
		expiresAt time.Time
	}
}

func (f *fakeRefreshTokens) Create(ctx context.Context, userID int64, tokenHash string, expiresAt time.Time) error {
	if f.created == nil {
		f.created = map[int64][]string{}
	}
	if f.byHash == nil {
		f.byHash = map[string]struct {
			userID    int64
			expiresAt time.Time
		}{}
	}
	f.created[userID] = append(f.created[userID], tokenHash)
	f.byHash[tokenHash] = struct {
		userID    int64
		expiresAt time.Time
	}{userID: userID, expiresAt: expiresAt}
	return nil
}

func (f *fakeRefreshTokens) DeleteByUser(ctx context.Context, userID int64) error {
	if f.created != nil {
		delete(f.created, userID)
	}
	if f.byHash != nil {
		for k, v := range f.byHash {
			if v.userID == userID {
				delete(f.byHash, k)
			}
		}
	}
	return nil
}

func (f *fakeRefreshTokens) GetByHash(ctx context.Context, tokenHash string) (int64, time.Time, error) {
	if f.byHash == nil {
		return 0, time.Time{}, errors.New("not found")
	}
	v, ok := f.byHash[tokenHash]
	if !ok {
		return 0, time.Time{}, errors.New("not found")
	}
	return v.userID, v.expiresAt, nil
}

func (f *fakeRefreshTokens) DeleteByHash(ctx context.Context, tokenHash string) error {
	if f.byHash != nil {
		delete(f.byHash, tokenHash)
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

type fakeRefreshIssuer struct {
	issued map[string]RefreshTokenClaims
	kid    string
}

func (f *fakeRefreshIssuer) KeyID() string { return f.kid }

func (f *fakeRefreshIssuer) Issue(ctx context.Context, claims RefreshTokenClaims) (string, error) {
	_ = ctx
	if f.issued == nil {
		f.issued = map[string]RefreshTokenClaims{}
	}
	if f.kid == "" {
		f.kid = "test-kid"
	}
	token := "rt:" + claims.ID
	f.issued[token] = claims
	return token, nil
}

func (f *fakeRefreshIssuer) Verify(ctx context.Context, token string) (RefreshTokenClaims, error) {
	_ = ctx
	claims, ok := f.issued[token]
	if !ok {
		return RefreshTokenClaims{}, errors.New("bad refresh token")
	}
	return claims, nil
}

func TestService_LoginLogoutAuthenticate(t *testing.T) {
	ctx := context.Background()

	users := &fakeUsers{}
	verifier := fakeVerifier{subject: "google-sub-1", profile: ExternalProfile{Email: "a@example.com", Name: "A"}}
	tokens := &fakeTokens{}
	refreshTokens := &fakeRefreshTokens{}
	refreshIssuer := &fakeRefreshIssuer{}
	blacklist := &fakeBlacklist{}

	svc := NewService(users, refreshTokens, verifier, tokens, refreshIssuer, blacklist, 5*time.Minute, 24*time.Hour)

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
		t.Fatalf("Authenticate UserID mismatch: got=%d want=%d", claims.UserID, res.User.ID)
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
	svc := NewService(&fakeUsers{}, &fakeRefreshTokens{}, fakeVerifier{err: errors.New("nope")}, &fakeTokens{}, &fakeRefreshIssuer{}, &fakeBlacklist{}, time.Minute, time.Hour)
	_, err := svc.LoginWithGoogle(context.Background(), "token")
	if !errors.Is(err, ErrInvalidCredential) {
		t.Fatalf("err = %v, want ErrInvalidCredential", err)
	}
}

func TestService_Refresh_RotatesToken(t *testing.T) {
	ctx := context.Background()

	users := &fakeUsers{}
	verifier := fakeVerifier{subject: "google-sub-1", profile: ExternalProfile{Email: "a@example.com", Name: "A"}}
	tokens := &fakeTokens{}
	refreshTokens := &fakeRefreshTokens{}
	refreshIssuer := &fakeRefreshIssuer{}

	svc := NewService(users, refreshTokens, verifier, tokens, refreshIssuer, nil, 5*time.Minute, 24*time.Hour)

	loginRes, err := svc.LoginWithGoogle(ctx, "id-token")
	if err != nil {
		t.Fatalf("LoginWithGoogle err = %v", err)
	}

	refRes, err := svc.Refresh(ctx, loginRes.RefreshToken)
	if err != nil {
		t.Fatalf("Refresh err = %v", err)
	}
	if refRes.AccessToken == "" || refRes.RefreshToken == "" {
		t.Fatalf("Refresh result incomplete: %+v", refRes)
	}
	if refRes.RefreshToken == loginRes.RefreshToken {
		t.Fatalf("Refresh token not rotated")
	}

	// Old refresh token should no longer work.
	if _, err := svc.Refresh(ctx, loginRes.RefreshToken); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("Refresh with old token err=%v want ErrUnauthorized", err)
	}
}

func TestService_Refresh_ChecksTokenVersion(t *testing.T) {
	ctx := context.Background()

	users := &fakeUsers{}
	verifier := fakeVerifier{subject: "google-sub-1", profile: ExternalProfile{Email: "a@example.com", Name: "A"}}
	tokens := &fakeTokens{}
	refreshTokens := &fakeRefreshTokens{}
	refreshIssuer := &fakeRefreshIssuer{}

	svc := NewService(users, refreshTokens, verifier, tokens, refreshIssuer, nil, 5*time.Minute, 24*time.Hour)

	loginRes, err := svc.LoginWithGoogle(ctx, "id-token")
	if err != nil {
		t.Fatalf("LoginWithGoogle err = %v", err)
	}

	// Simulate global logout by bumping user's token_version; refresh should fail.
	_ = users.IncrementTokenVersion(ctx, users.user.ID)

	if _, err := svc.Refresh(ctx, loginRes.RefreshToken); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("Refresh err=%v want ErrUnauthorized", err)
	}

	// Sanity: refresh token subject is a user id string.
	sub := refreshIssuer.issued[loginRes.RefreshToken].Subject
	if _, err := strconv.ParseInt(sub, 10, 64); err != nil {
		t.Fatalf("refresh subject not int64: %q", sub)
	}
}
