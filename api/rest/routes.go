package rest

import (
	"net/http"
	"time"

	"auth-service/internal/auth"
	applogger "auth-service/pkg/logger"

	"github.com/gin-gonic/gin"
)

const (
	pathPasetoKeys = "/.well-known/paseto-keys.json"
)

type Dependencies struct {
	AuthService           *auth.Service
	Logger                *applogger.Logger
	PasetoPublicKeyBase64 string
	PasetoPublicKeyIAT    time.Time
	AccessTokenKID        string
	RefreshTokenKID       string
}

func RegisterRoutes(engine *gin.Engine, deps Dependencies) {
	keysHandler := NewPasetoKeysHandler(
		deps.PasetoPublicKeyBase64,
		deps.PasetoPublicKeyIAT,
		[]string{deps.AccessTokenKID, deps.RefreshTokenKID},
	)
	engine.GET(pathPasetoKeys, keysHandler.Get)

	engine.GET("/healthcheck", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"status": "ok"})
	})

	authHandler := NewAuthHandler(deps.AuthService, deps.Logger.Named("auth-handler"))

	v1 := engine.Group("/api/v1")

	authRoutes := v1.Group("/auth")
	authRoutes.POST("/google/login", authHandler.GoogleLogin)
	authRoutes.POST("/refresh", authHandler.Refresh)
	authRoutes.POST("/logout", authHandler.Logout)
	authRoutes.POST("/authenticate", authHandler.Authenticate)
}

func respondJSON(c *gin.Context, status int, payload any) {
	c.JSON(status, gin.H{"data": payload})
}

func respondError(c *gin.Context, status int, message string) {
	c.JSON(status, gin.H{"error": message})
}
