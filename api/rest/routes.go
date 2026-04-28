package rest

import (
	"net/http"

	"auth-service/internal/auth"
	applogger "auth-service/pkg/logger"

	"github.com/gin-gonic/gin"
)

type Dependencies struct {
	AuthService *auth.Service
	Logger      *applogger.Logger
}

func RegisterRoutes(engine *gin.Engine, deps Dependencies) {
	engine.GET("/healthcheck", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"status": "ok"})
	})

	authHandler := NewAuthHandler(deps.AuthService, deps.Logger.Named("auth-handler"))

	v1 := engine.Group("/api/v1")

	authRoutes := v1.Group("/auth")
	authRoutes.POST("/google/login", authHandler.GoogleLogin)
	authRoutes.POST("/logout", authHandler.Logout)
}

func respondJSON(c *gin.Context, status int, payload any) {
	c.JSON(status, gin.H{"data": payload})
}

func respondError(c *gin.Context, status int, message string) {
	c.JSON(status, gin.H{"error": message})
}
