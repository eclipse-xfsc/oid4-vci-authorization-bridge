package database

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/eclipse-xfsc/oid4-vci-authorization-bridge/v2/pkg/messaging"

	ctxPkg "github.com/eclipse-xfsc/microservice-core-go/pkg/ctx"
	redisPkg "github.com/eclipse-xfsc/microservice-core-go/pkg/db/redis"
	errPkg "github.com/eclipse-xfsc/microservice-core-go/pkg/err"
	"github.com/redis/go-redis/v9"
)

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

	return &RedisDB{
		client: client,
	}, nil
}

func (r *RedisDB) SaveAuth(ctx context.Context, key string, authentication messaging.Authentication, ttl time.Duration) error {
	js, err := json.Marshal(authentication)
	if err != nil {
		return fmt.Errorf("failed to marshal json: %w", err)
	}

	if err := r.client.Rdb.Set(ctx, key, string(js), ttl).Err(); err != nil {
		return err
	}

	return nil
}

func (r *RedisDB) GetAuth(ctx context.Context, key string) (*messaging.Authentication, error) {
	js, err := r.client.Rdb.Get(ctx, key).Result()
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
	result, err := r.client.Rdb.Del(ctx, key).Result()
	if err != nil {
		if errors.Is(err, redis.Nil) {
			return false, ErrKeyNotFound
		}

		return false, err
	}

	if result > 0 {
		return true, nil
	}

	return false, nil
}
