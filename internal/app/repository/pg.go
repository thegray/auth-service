package repository

import (
	"context"
	"errors"
	"fmt"
	"time"

	"auth-service/internal/app"

	"github.com/redis/go-redis/v9"
	"gorm.io/gorm"
)

const (
	cacheKeyPrefix = "clientid"
	cacheTTL       = 24 * time.Hour
)

type PostgresAppRepository struct {
	db    *gorm.DB
	redis *redis.Client
}

func NewPostgresAppRepository(db *gorm.DB, redisClient *redis.Client) *PostgresAppRepository {
	return &PostgresAppRepository{db: db, redis: redisClient}
}

func (r *PostgresAppRepository) AutoMigrate() error {
	return r.db.AutoMigrate(&pgApp{})
}

func (r *PostgresAppRepository) GetByName(ctx context.Context, name string) (*app.App, error) {
	var row pgApp
	if err := r.db.WithContext(ctx).First(&row, "name = ?", name).Error; err != nil {
		return nil, err
	}
	return row.toDomain(), nil
}

func (r *PostgresAppRepository) Create(ctx context.Context, a *app.App) error {
	return r.db.WithContext(ctx).Create(fromDomain(a)).Error
}

func (r *PostgresAppRepository) GetClientID(ctx context.Context, id string, provider string) (string, error) {
	if r.redis != nil {
		cached, err := r.redis.Get(ctx, cacheKey(provider, id)).Result()
		if err == nil {
			return cached, nil
		}
		if !errors.Is(err, redis.Nil) {
			return "", err
		}
	}

	var row pgApp
	if err := r.db.WithContext(ctx).First(&row, "id = ? AND provider = ?", id, provider).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return "", nil
		}
		return "", err
	}

	if r.redis != nil {
		r.redis.Set(ctx, cacheKey(provider, id), row.ClientID, cacheTTL)
	}

	return row.ClientID, nil
}

func cacheKey(provider, id string) string {
	return fmt.Sprintf("%s:%s:%s", cacheKeyPrefix, provider, id)
}
