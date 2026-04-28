package repository

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"auth-service/internal/auth"

	"github.com/redis/go-redis/v9"
)

var ErrRedisClientNil = errors.New("redis client is nil")

type RedisBlacklist struct {
	client *redis.Client
	prefix string
}

func NewRedisBlacklist(client *redis.Client, prefix string) *RedisBlacklist {
	prefix = strings.TrimSpace(prefix)
	if prefix == "" {
		prefix = "auth"
	}
	return &RedisBlacklist{client: client, prefix: prefix}
}

func (r *RedisBlacklist) Revoke(ctx context.Context, tokenID string, expiresAt time.Time) error {
	if r.client == nil {
		return ErrRedisClientNil
	}
	tokenID = strings.TrimSpace(tokenID)
	if tokenID == "" {
		return nil
	}

	ttl := time.Until(expiresAt)
	if ttl <= 0 {
		ttl = time.Second
	}

	return r.client.Set(ctx, r.key(tokenID), "1", ttl).Err()
}

func (r *RedisBlacklist) IsRevoked(ctx context.Context, tokenID string) (bool, error) {
	if r.client == nil {
		return false, ErrRedisClientNil
	}
	tokenID = strings.TrimSpace(tokenID)
	if tokenID == "" {
		return false, nil
	}

	n, err := r.client.Exists(ctx, r.key(tokenID)).Result()
	if err != nil {
		return false, err
	}
	return n > 0, nil
}

func (r *RedisBlacklist) key(tokenID string) string {
	return fmt.Sprintf("%s:revoked:%s", r.prefix, tokenID)
}

var _ auth.BlacklistStore = (*RedisBlacklist)(nil)
