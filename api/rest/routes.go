package rest

import (
	"net/http"

	"auth-service/internal/order"
	"auth-service/internal/usecase/checkout"
	"auth-service/internal/user"
	applogger "auth-service/pkg/logger"

	"github.com/gin-gonic/gin"
)

type Dependencies struct {
	UserService     *user.Service
	OrderService    *order.Service
	CheckoutService *checkout.Service
	Logger          *applogger.Logger
}

func RegisterRoutes(engine *gin.Engine, deps Dependencies) {
	engine.GET("/healthcheck", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"status": "ok"})
	})

	userHandler := NewUserHandler(deps.UserService, deps.Logger.Named("user-handler"))

	v1 := engine.Group("/api/v1")

	users := v1.Group("/users")
	users.POST("/login", userHandler.Login)
	users.GET("/:id", userHandler.GetByID)
}

func respondJSON(c *gin.Context, status int, payload any) {
	c.JSON(status, gin.H{"data": payload})
}

func respondError(c *gin.Context, status int, message string) {
	c.JSON(status, gin.H{"error": message})
}
