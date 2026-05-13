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
	"auth-service/internal/app"
	apprepo "auth-service/internal/app/repository"
	"auth-service/internal/auth"
	authrepo "auth-service/internal/auth/repository"
	authtoken "auth-service/internal/auth/token"
	"auth-service/internal/infra"
	"auth-service/internal/token"
	"auth-service/internal/usecase/login"
	applogger "auth-service/pkg/logger"

	"github.com/gin-gonic/gin"
	"github.com/joho/godotenv"
	"gorm.io/gorm"
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

	clock := auth.ServiceClock{}
	authRepository := authrepo.NewPostgres(db, appLogger.Named("auth-db"), cfg.MachineID, clock)

	// TODO: add proper migration
	serverLogger.Info("running auth db migrations")
	if err := authRepository.AutoMigrate(); err != nil {
		return fmt.Errorf("auth db migration failed: %w", err)
	}

	redisClient, err := infra.NewRedisClient(ctx, infra.RedisConfig{
		Host:     cfg.RedisHost,
		Port:     cfg.RedisPort,
		Password: cfg.RedisPassword,
		DB:       cfg.RedisDB,
	})
	if err != nil {
		return err
	}
	defer func() {
		_ = redisClient.Close()
	}()

	appRepository := apprepo.NewPostgresAppRepository(db, redisClient)

	// TODO: add proper migration
	serverLogger.Info("running app db migrations")
	if err := appRepository.AutoMigrate(); err != nil {
		return fmt.Errorf("app db migration failed: %w", err)
	}
	// TODO: move seeder to script
	serverLogger.Info("seeding app db")
	if err := seedGoogleApp(ctx, appRepository, cfg.GoogleClientID, cfg.AppEnv, serverLogger); err != nil {
		return err
	}

	blacklist := authrepo.NewRedisBlacklist(redisClient, "")
	googleVerifier := token.NewVerifier(appRepository)
	accessIssuer, err := authtoken.NewPasetoV4PublicAccessKIDIssuer(cfg.AccessTokenKID, cfg.PasetoV4PrivateKey, cfg.PasetoV4PublicKey, appLogger)
	if err != nil {
		return err
	}
	refreshIssuer, err := authtoken.NewPasetoV4PublicKIDIssuer(cfg.RefreshTokenKID, cfg.PasetoV4PrivateKey, cfg.PasetoV4PublicKey, appLogger)
	if err != nil {
		return err
	}

	authService := auth.NewService(
		authRepository,
		authRepository,
		accessIssuer,
		refreshIssuer,
		blacklist,
		clock,
		cfg.AccessTokenTTL,
		cfg.RefreshTokenTTL,
		appLogger,
	)

	loginUsecase := login.NewService(
		googleVerifier,
		authRepository,
		authRepository,
		accessIssuer,
		refreshIssuer,
		clock,
		cfg.AccessTokenTTL,
		cfg.RefreshTokenTTL,
		appLogger,
	)

	engine := gin.New()
	engine.Use(gin.Recovery())
	engine.Use(applogger.GinMiddleware(appLogger.Named("http")))
	rest.RegisterRoutes(engine, rest.Dependencies{
		AuthService:           authService,
		LoginUsecase:          loginUsecase,
		Logger:                appLogger.Named("rest"),
		PasetoPublicKeyBase64: cfg.PasetoV4PublicKey,
		PasetoPublicKeyIAT:    cfg.PasetoPublicKeyIAT,
		AccessTokenKID:        cfg.AccessTokenKID,
		RefreshTokenKID:       cfg.RefreshTokenKID,
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
		serverLogger.Sugar().Infow("server starting", "address", address)
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

func seedGoogleApp(ctx context.Context, repo *apprepo.PostgresAppRepository, clientID, appEnv string, log *applogger.Logger) error {
	if clientID == "" {
		return nil
	}
	_, err := repo.GetByName(ctx, "google")
	if err == nil {
		return nil // already seeded
	}
	if !errors.Is(err, gorm.ErrRecordNotFound) {
		return fmt.Errorf("check google app: %w", err)
	}
	if appEnv == "" {
		appEnv = "development"
	}
	seed := &app.App{
		Name:     "google",
		ClientID: clientID,
		Provider: "google",
		Status:   "active",
		Env:      appEnv,
	}
	if err := repo.Create(ctx, seed); err != nil {
		return fmt.Errorf("seed google app: %w", err)
	}
	log.Info("seeded google oauth app from environment")
	return nil
}
