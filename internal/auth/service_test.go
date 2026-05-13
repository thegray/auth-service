package auth

import (
	"context"
	"errors"
	"testing"
	"time"

	"auth-service/internal/shared"
	applogger "auth-service/pkg/logger"
)

type fakeUsers struct {
	user *User
	err  error
}

func (f *fakeUsers) UpsertByProvider(ctx context.Context, provider shared.Provider, subject string, profile shared.ExternalProfile) (*User, error) {
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

type fakeServiceClock struct{}

func (fakeServiceClock) Now() time.Time {
	return time.Now()
}

func newTestService(users *fakeUsers, refreshTokens *fakeRefreshTokens, tokens *fakeTokens, refreshIssuer *fakeRefreshIssuer, blacklist *fakeBlacklist) *Service {
	return NewService(users, refreshTokens, tokens, refreshIssuer, blacklist, fakeServiceClock{}, 5*time.Minute, 24*time.Hour, applogger.Wrap(nil))
}

func TestService_Authenticate_ValidToken(t *testing.T) {
	ctx := context.Background()
	tokens := &fakeTokens{}
	svc := newTestService(&fakeUsers{}, &fakeRefreshTokens{}, tokens, &fakeRefreshIssuer{}, &fakeBlacklist{})

	// Issue a token manually via fake and authenticate it.
	issued, _ := tokens.Issue(ctx, TokenClaims{UserID: 123})
	if _, err := svc.Authenticate(ctx, issued); err != nil {
		t.Fatalf("Expected no error, got = %v", err)
	}
}

func TestService_Authenticate_InvalidToken(t *testing.T) {
	svc := newTestService(&fakeUsers{}, &fakeRefreshTokens{}, &fakeTokens{}, &fakeRefreshIssuer{}, &fakeBlacklist{})
	_, err := svc.Authenticate(context.Background(), "bad-token")
	if !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("err = %v, want ErrUnauthorized", err)
	}
}

func TestService_Authenticate_RevokedToken(t *testing.T) {
	ctx := context.Background()
	tokens := &fakeTokens{}
	blacklist := &fakeBlacklist{}
	svc := newTestService(&fakeUsers{}, &fakeRefreshTokens{}, tokens, &fakeRefreshIssuer{}, blacklist)

	issued, _ := tokens.Issue(ctx, TokenClaims{UserID: 123, TokenID: "test-jti", ExpiresAt: time.Now().Add(5 * time.Minute)})
	_ = blacklist.Revoke(ctx, "test-jti", time.Now().Add(5*time.Minute))
	_, err := svc.Authenticate(ctx, issued)
	if !errors.Is(err, ErrTokenRevoked) {
		t.Fatalf("err = %v, want ErrTokenRevoked", err)
	}
}

func TestService_Logout_InvalidatesTokens(t *testing.T) {
	ctx := context.Background()
	users := &fakeUsers{}
	// Create a user so IncrementTokenVersion works.
	users.UpsertByProvider(ctx, shared.ProviderGoogle, "sub-1", shared.ExternalProfile{Email: "a@b.com"})
	tokens := &fakeTokens{}
	blacklist := &fakeBlacklist{}
	refreshTokens := &fakeRefreshTokens{}
	refreshIssuer := &fakeRefreshIssuer{}
	svc := newTestService(users, refreshTokens, tokens, refreshIssuer, blacklist)

	issued, _ := tokens.Issue(ctx, TokenClaims{UserID: 1, TokenID: "jti-1", ExpiresAt: time.Now().Add(5 * time.Minute)})
	if err := svc.Logout(ctx, issued, ""); err != nil {
		t.Fatalf("Logout err = %v", err)
	}
	if _, ok := blacklist.revoked["jti-1"]; !ok {
		t.Fatalf("access token not revoked")
	}
	// Logout already increments token_version once.
	if users.user.TokenVersion != 2 {
		t.Fatalf("token_version = %d, want 2", users.user.TokenVersion)
	}
}

func TestService_Logout_InvalidToken(t *testing.T) {
	svc := newTestService(&fakeUsers{}, &fakeRefreshTokens{}, &fakeTokens{}, &fakeRefreshIssuer{}, &fakeBlacklist{})
	if err := svc.Logout(context.Background(), "", ""); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("err = %v, want ErrUnauthorized", err)
	}
}

func TestService_Refresh_RotatesToken(t *testing.T) {
	ctx := context.Background()
	users := &fakeUsers{}
	tokens := &fakeTokens{}
	refreshTokens := &fakeRefreshTokens{}
	refreshIssuer := &fakeRefreshIssuer{}
	svc := newTestService(users, refreshTokens, tokens, refreshIssuer, nil)

	// Simulate a login by issuing a refresh token and persisting its hash.
	_, _ = users.UpsertByProvider(ctx, shared.ProviderGoogle, "sub-1", shared.ExternalProfile{Email: "a@b.com"})
	rtClaims := RefreshTokenClaims{
		ID:      "rt-1",
		Subject: "1",
		Version: users.user.TokenVersion,
		Type:    "refresh",
	}
	refreshToken, _ := refreshIssuer.Issue(ctx, rtClaims)
	_ = refreshTokens.Create(ctx, 1, hashToken(refreshToken), time.Now().Add(24*time.Hour))

	refRes, err := svc.Refresh(ctx, refreshToken)
	if err != nil {
		t.Fatalf("Refresh err = %v", err)
	}
	if refRes.AccessToken == "" || refRes.RefreshToken == "" {
		t.Fatalf("Refresh result incomplete: %+v", refRes)
	}
	if refRes.RefreshToken == refreshToken {
		t.Fatalf("Refresh token not rotated")
	}

	// Old refresh token should no longer work.
	if _, err := svc.Refresh(ctx, refreshToken); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("Refresh with old token err=%v want ErrUnauthorized", err)
	}
}

func TestService_Refresh_ChecksTokenVersion(t *testing.T) {
	ctx := context.Background()
	users := &fakeUsers{}
	tokens := &fakeTokens{}
	refreshTokens := &fakeRefreshTokens{}
	refreshIssuer := &fakeRefreshIssuer{}
	svc := newTestService(users, refreshTokens, tokens, refreshIssuer, nil)

	_, _ = users.UpsertByProvider(ctx, shared.ProviderGoogle, "sub-1", shared.ExternalProfile{Email: "a@b.com"})
	rtClaims := RefreshTokenClaims{
		ID:      "rt-1",
		Subject: "1",
		Version: users.user.TokenVersion,
		Type:    "refresh",
	}
	refreshToken, _ := refreshIssuer.Issue(ctx, rtClaims)
	_ = refreshTokens.Create(ctx, 1, hashToken(refreshToken), time.Now().Add(24*time.Hour))

	// Simulate global logout by bumping token_version.
	_ = users.IncrementTokenVersion(ctx, 1)

	if _, err := svc.Refresh(ctx, refreshToken); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("Refresh err=%v want ErrUnauthorized", err)
	}
}
