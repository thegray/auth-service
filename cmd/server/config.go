package main

import (
	"auth-service/pkg/idgenerator"
	"os"
	"strconv"
	"time"
)

const (
	envRedisHost     = "REDIS_HOST"
	envRedisPort     = "REDIS_PORT"
	envRedisPassword = "REDIS_PASSWORD"
	envRedisDB       = "REDIS_DB"

	envGoogleClientID     = "GOOGLE_CLIENT_ID"
	envAccessTTLMinutes   = "ACCESS_TOKEN_TTL_MINUTES"
	envRefreshTTLDays     = "REFRESH_TOKEN_TTL_DAYS"
	envAccessTokenKID     = "ACCESS_TOKEN_KID"
	envRefreshTokenKID    = "REFRESH_TOKEN_KID"
	envPasetoPublicKeyIAT = "PASETO_PUBLIC_KEY_IAT"

	envPasetoV4PrivateKey = "PASETO_V4_PRIVATE_KEY"
	envPasetoV4PublicKey  = "PASETO_V4_PUBLIC_KEY"
	envMachineID          = "MACHINE_ID"

	defaultAccessTTLMinutes = 15
	defaultRefreshTTLDays   = 30
	defaultMachineID        = 0
	defaultRefreshTokenKID  = "refresh-v1"
	defaultAccessTokenKID   = "access-v1"

	// maxMachineIDv1 is the maximum value that can fit in the ReservedBits.
	maxMachineIDv1 = -1 ^ (-1 << idgenerator.ReservedBits)
)

type config struct {
	ServerHost string
	ServerPort string
	LogEnv     string
	AppEnv     string

	DBHost        string
	DBPort        string
	DBName        string
	DBUser        string
	DBPassword    string
	DBSSLMode     string
	MaxConns      int32
	MinConns      int32
	RedisHost     string
	RedisPort     string
	RedisPassword string
	RedisDB       int

	GoogleClientID     string
	PasetoV4PrivateKey string
	PasetoV4PublicKey  string
	AccessTokenTTL     time.Duration
	RefreshTokenTTL    time.Duration
	PasetoPublicKeyIAT time.Time
	MachineID          int64
	AccessTokenKID     string
	RefreshTokenKID    string
}

func loadConfig() config {
	accessTTLMinutes := getEnvInt(envAccessTTLMinutes, defaultAccessTTLMinutes)
	refreshTTLDays := getEnvInt(envRefreshTTLDays, defaultRefreshTTLDays)
	machineID := getEnvInt64(envMachineID, defaultMachineID)
	if machineID < 0 || machineID > maxMachineIDv1 {
		machineID = defaultMachineID
	}
	accessTokenKID := getEnv(envAccessTokenKID, defaultAccessTokenKID)
	refreshTokenKID := getEnv(envRefreshTokenKID, defaultRefreshTokenKID)
	publicKeyIAT := getEnvTime(envPasetoPublicKeyIAT, time.Now().UTC())

	return config{
		ServerHost:         getEnv("SERVER_HOST", "0.0.0.0"),
		ServerPort:         getEnv("SERVER_PORT", "8080"),
		LogEnv:             getEnv("LOG_ENV", "production"),
		DBHost:             getEnv("DB_HOST", "localhost"),
		DBPort:             getEnv("DB_PORT", "5432"),
		DBName:             getEnv("DB_NAME", "develop"),
		DBUser:             getEnv("DB_USER", "postgres"),
		DBPassword:         getEnv("DB_PASSWORD", "postgres"),
		DBSSLMode:          getEnv("DB_SSLMODE", "disable"),
		MaxConns:           getEnvInt32("DB_MAX_CONNS", 10),
		MinConns:           getEnvInt32("DB_MIN_CONNS", 1),
		AppEnv:             getEnv("APP_ENV", "development"),
		GoogleClientID:     getEnv(envGoogleClientID, ""),
		PasetoV4PrivateKey: getEnv(envPasetoV4PrivateKey, ""),
		PasetoV4PublicKey:  getEnv(envPasetoV4PublicKey, ""),
		AccessTokenTTL:     time.Duration(accessTTLMinutes) * time.Minute,
		RefreshTokenTTL:    time.Duration(refreshTTLDays) * 24 * time.Hour,
		MachineID:          machineID,
		AccessTokenKID:     accessTokenKID,
		RefreshTokenKID:    refreshTokenKID,
		PasetoPublicKeyIAT: publicKeyIAT,
		RedisHost:          getEnv(envRedisHost, "localhost"),
		RedisPort:          getEnv(envRedisPort, "6379"),
		RedisPassword:      getEnv(envRedisPassword, ""),
		RedisDB:            getEnvInt(envRedisDB, 0),
	}
}

func getEnv(key, fallback string) string {
	value := os.Getenv(key)
	if value == "" {
		return fallback
	}
	return value
}

func getEnvInt32(key string, fallback int32) int32 {
	value := os.Getenv(key)
	if value == "" {
		return fallback
	}

	parsed, err := strconv.Atoi(value)
	if err != nil {
		return fallback
	}
	return int32(parsed)
}

func getEnvInt(key string, fallback int) int {
	value := os.Getenv(key)
	if value == "" {
		return fallback
	}

	parsed, err := strconv.Atoi(value)
	if err != nil {
		return fallback
	}
	return parsed
}

func getEnvInt64(key string, fallback int64) int64 {
	value := os.Getenv(key)
	if value == "" {
		return fallback
	}

	parsed, err := strconv.ParseInt(value, 10, 64)
	if err != nil {
		return fallback
	}
	return parsed
}

func getEnvTime(key string, fallback time.Time) time.Time {
	value := os.Getenv(key)
	if value == "" {
		return fallback
	}
	parsed, err := time.Parse(time.RFC3339, value)
	if err != nil {
		return fallback
	}
	return parsed.UTC()
}
