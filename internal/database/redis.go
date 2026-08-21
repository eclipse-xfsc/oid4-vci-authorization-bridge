package database

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"time"

	ctxPkg "github.com/eclipse-xfsc/microservice-core-go/pkg/ctx"
	redisPkg "github.com/eclipse-xfsc/microservice-core-go/pkg/db/redis"
	errPkg "github.com/eclipse-xfsc/microservice-core-go/pkg/err"
	"github.com/eclipse-xfsc/oid4-vci-authorization-bridge/v2/pkg/messaging"
	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
)

const keyPrefix = "auth:"

type RedisDB struct {
	client *redisPkg.Client
}

func NewRedisDB(ctx context.Context, config redisPkg.Config) (*RedisDB, error) {
	logger := ctxPkg.GetLogger(ctx)

	errChan := make(chan error)
	go errPkg.LogChan(logger, errChan)
	logger.Info("Connect to " + config.Hosts + ":" + strconv.Itoa(config.Port))
	client, err := redisPkg.ConnectRetry(ctx, config, time.Minute, errChan)

	if err != nil {
		return nil, err
	}

	return &RedisDB{client: client}, nil
}

func (r *RedisDB) SaveAuth(ctx context.Context, key string, authentication messaging.Authentication, ttl time.Duration) error {
	js, err := json.Marshal(authentication)
	if err != nil {
		return fmt.Errorf("failed to marshal json: %w", err)
	}

	if err := r.client.Rdb.Set(ctx, keyPrefix+key, string(js), ttl).Err(); err != nil {
		return err
	}

	return nil
}

func (r *RedisDB) GetAuth(ctx context.Context, key string) (*messaging.Authentication, error) {
	js, err := r.client.Rdb.Get(ctx, keyPrefix+key).Result()
	if err != nil {
		if errors.Is(err, redis.Nil) {
			return nil, ErrKeyNotFound
		}

		return nil, err
	}

	var auth messaging.Authentication
	if err := json.Unmarshal([]byte(js), &auth); err != nil {
		return nil, err
	}

	return &auth, nil
}

func (r *RedisDB) DeleteAuth(ctx context.Context, key string) (bool, error) {
	result, err := r.client.Rdb.Del(ctx, keyPrefix+key).Result()
	if err != nil {
		if errors.Is(err, redis.Nil) {
			return false, ErrKeyNotFound
		}

		return false, err
	}

	return result > 0, nil
}

func (r *RedisDB) Health(ctx context.Context) error {
	key := keyPrefix + "health:" + uuid.NewString()
	value := uuid.NewString()

	if err := r.client.Rdb.Set(ctx, key, value, 10*time.Second).Err(); err != nil {
		return fmt.Errorf("redis health write failed: %w", err)
	}

	got, err := r.client.Rdb.Get(ctx, key).Result()
	if err != nil {
		return fmt.Errorf("redis health read failed: %w", err)
	}
	if got != value {
		return fmt.Errorf("redis health value mismatch")
	}

	if err := r.client.Rdb.Del(ctx, key).Err(); err != nil {
		return fmt.Errorf("redis health cleanup failed: %w", err)
	}

	return nil
}
