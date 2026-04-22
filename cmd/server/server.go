package main

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"auth-service/api/rest"
	"auth-service/internal/infra"
	"auth-service/internal/order"
	orderrepo "auth-service/internal/order/repository"
	"auth-service/internal/usecase/checkout"
	"auth-service/internal/user"
	userrepo "auth-service/internal/user/repository"
	pkgcrypto "auth-service/pkg/crypto"
	applogger "auth-service/pkg/logger"

	"github.com/gin-gonic/gin"
	"github.com/joho/godotenv"
)

func runServer(ctx context.Context) error {
	_ = godotenv.Load()

	cfg := loadConfig()

	logger, err := applogger.New(cfg.LogEnv)
	if err != nil {
		return err
	}
	appLogger := applogger.Wrap(logger)
	defer func() {
		_ = appLogger.Sync()
	}()
	serverLogger := appLogger.Named("server")

	db, err := infra.NewPostgresPool(ctx, infra.PostgresConfig{
		Host:     cfg.DBHost,
		Port:     cfg.DBPort,
		Database: cfg.DBName,
		User:     cfg.DBUser,
		Password: cfg.DBPassword,
		SSLMode:  cfg.DBSSLMode,
		MaxConns: cfg.MaxConns,
		MinConns: cfg.MinConns,
	})
	if err != nil {
		return err
	}

	userRepository := userrepo.New(db, appLogger.Named("user-db"))
	orderRepository := orderrepo.New(db, appLogger.Named("order-db"))
	passwordHasher := pkgcrypto.NewBcryptHasher(0)

	userService := user.NewService(userRepository, passwordHasher, appLogger.Named("user-service"))
	orderService := order.NewService(orderRepository, appLogger.Named("order-service"))
	checkoutService := checkout.NewService(userService, orderService, appLogger.Named("checkout-service"))

	engine := gin.New()
	engine.Use(gin.Recovery())
	engine.Use(applogger.GinMiddleware(appLogger.Named("http")))
	rest.RegisterRoutes(engine, rest.Dependencies{
		UserService:     userService,
		OrderService:    orderService,
		CheckoutService: checkoutService,
		Logger:          appLogger.Named("rest"),
	})

	address := fmt.Sprintf("%s:%s", cfg.ServerHost, cfg.ServerPort)
	httpServer := &http.Server{
		Addr:    address,
		Handler: engine,
	}

	errCh := make(chan error, 1)
	stopCh := make(chan os.Signal, 1)
	signal.Notify(stopCh, syscall.SIGINT, syscall.SIGTERM)
	defer signal.Stop(stopCh)

	go func() {
		serverLogger.Sugar().Infow("server listening", "address", address)
		if err := httpServer.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
		}
		close(errCh)
	}()

	select {
	case <-ctx.Done():
		serverLogger.Info("shutdown requested by context")
	case sig := <-stopCh:
		serverLogger.Sugar().Infow("shutdown signal received", "signal", sig.String())
	case err := <-errCh:
		if err != nil {
			return err
		}
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	serverLogger.Info("server shutting down")
	if err := httpServer.Shutdown(shutdownCtx); err != nil {
		return err
	}

	serverLogger.Info("server shutdown complete")
	return nil
}
