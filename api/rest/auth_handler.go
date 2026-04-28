package rest

import (
	"net/http"
	"strings"

	"auth-service/internal/auth"
	applogger "auth-service/pkg/logger"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
)

const (
	errInvalidRequest    = "invalid request"
	errInvalidCredential = "invalid credential"
	errInternal          = "internal error"
	tokenTypeBearer      = "Bearer"
)

type AuthHandler struct {
	auth *auth.Service
	log  *applogger.Logger
}

func NewAuthHandler(authSvc *auth.Service, log *applogger.Logger) *AuthHandler {
	if log == nil {
		log = applogger.Wrap(zap.NewNop())
	}
	return &AuthHandler{auth: authSvc, log: log}
}

func (h *AuthHandler) GoogleLogin(c *gin.Context) {
	if h.auth == nil {
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

	result, err := h.auth.LoginWithGoogle(c.Request.Context(), req.IDToken)
	if err != nil {
		switch err {
		case auth.ErrInvalidCredential:
			respondError(c, http.StatusUnauthorized, errInvalidCredential)
		default:
			h.log.ErrorCtx(c.Request.Context(), "google login failed", zap.Error(err))
			respondError(c, http.StatusInternalServerError, errInternal)
		}
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

// Phase 1 handler stub: will be fully implemented after blacklist store is wired.
func (h *AuthHandler) Logout(c *gin.Context) {
	respondError(c, http.StatusNotImplemented, "not implemented")
}
