package rest

import (
	"errors"
	"net/http"
	"strings"

	"auth-service/internal/auth"
	"auth-service/internal/usecase/login"
	applogger "auth-service/pkg/logger"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
)

const (
	errInvalidRequest    = "invalid request"
	errInvalidCredential = "invalid credential"
	errInternal          = "internal error"
	tokenTypeBearer      = "Bearer"
	errUnauthorized      = "unauthorized"
)

type AuthHandler struct {
	auth  *auth.Service
	login *login.Service
	log   *applogger.Logger
}

func NewAuthHandler(authSvc *auth.Service, loginSvc *login.Service, log *applogger.Logger) *AuthHandler {
	if log == nil {
		log = applogger.Wrap(zap.NewNop())
	}
	return &AuthHandler{auth: authSvc, login: loginSvc, log: log}
}

func (h *AuthHandler) GoogleLogin(c *gin.Context) {
	if h.login == nil {
		respondError(c, http.StatusInternalServerError, errInternal)
		return
	}

	var req googleLoginRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		respondError(c, http.StatusBadRequest, errInvalidRequest)
		return
	}
	if strings.TrimSpace(req.IDToken) == "" {
		respondError(c, http.StatusBadRequest, errInvalidRequest)
		return
	}

	result, err := h.login.LoginWithGoogle(c.Request.Context(), req.AppID, req.IDToken)
	if err != nil {
		h.handleError(c, err, "google login failed")
		return
	}

	respondJSON(c, http.StatusOK, googleLoginResponse{
		TokenType:    tokenTypeBearer,
		AccessToken:  result.AccessToken,
		RefreshToken: result.RefreshToken,
		ExpiresAt:    result.ExpiresAt,
		User: authUserResponse{
			ID:          result.User.ID,
			Email:       result.User.Email,
			DisplayName: result.User.Name,
		},
	})
}

func (h *AuthHandler) Logout(c *gin.Context) {
	if h.auth == nil {
		respondError(c, http.StatusInternalServerError, errInternal)
		return
	}

	token := bearerTokenFromHeader(c.GetHeader("Authorization"))
	if token == "" {
		respondError(c, http.StatusUnauthorized, errUnauthorized)
		return
	}

	if err := h.auth.Logout(c.Request.Context(), token); err != nil {
		h.handleError(c, err, "logout failed")
		return
	}

	c.Status(http.StatusNoContent)
}

func (h *AuthHandler) Refresh(c *gin.Context) {
	if h.auth == nil {
		respondError(c, http.StatusInternalServerError, errInternal)
		return
	}

	var req refreshRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		respondError(c, http.StatusBadRequest, errInvalidRequest)
		return
	}
	if strings.TrimSpace(req.RefreshToken) == "" {
		respondError(c, http.StatusBadRequest, errInvalidRequest)
		return
	}

	result, err := h.auth.Refresh(c.Request.Context(), req.RefreshToken)
	if err != nil {
		h.handleError(c, err, "refresh failed")
		return
	}

	respondJSON(c, http.StatusOK, refreshResponse{
		TokenType:    tokenTypeBearer,
		AccessToken:  result.AccessToken,
		RefreshToken: result.RefreshToken,
		ExpiresAt:    result.ExpiresAt,
		User: authUserResponse{
			ID:          result.User.ID,
			Email:       result.User.Email,
			DisplayName: result.User.Name,
		},
	})
}

func (h *AuthHandler) Authenticate(c *gin.Context) {
	if h.auth == nil {
		respondError(c, http.StatusInternalServerError, errInternal)
		return
	}

	token := bearerTokenFromHeader(c.GetHeader("Authorization"))
	if token == "" {
		respondError(c, http.StatusUnauthorized, errUnauthorized)
		return
	}

	claims, err := h.auth.Authenticate(c.Request.Context(), token)
	if err != nil {
		h.handleError(c, err, "authentication failed")
		return
	}

	respondJSON(c, http.StatusOK, gin.H{
		"user_id": claims.UserID,
		"email":   claims.Email,
		"exp":     claims.ExpiresAt,
	})
}

func (h *AuthHandler) handleError(c *gin.Context, err error, msg string) {
	switch {
	case errors.Is(err, auth.ErrInvalidCredential):
		respondError(c, http.StatusUnauthorized, errInvalidCredential)
	case errors.Is(err, auth.ErrUnauthorized),
		errors.Is(err, auth.ErrTokenRevoked):
		respondError(c, http.StatusUnauthorized, errUnauthorized)
	default:
		h.log.ErrorCtx(c.Request.Context(), msg, zap.Error(err))
		respondError(c, http.StatusInternalServerError, errInternal)
	}
}

func bearerTokenFromHeader(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}

	const prefix = tokenTypeBearer + " "
	if !strings.HasPrefix(value, prefix) {
		return ""
	}

	return strings.TrimSpace(strings.TrimPrefix(value, prefix))
}
