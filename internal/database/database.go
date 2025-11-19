package database

import (
	"context"
	"fmt"
	"time"

	"github.com/eclipse-xfsc/oid4-vci-authorization-bridge/v2/pkg/messaging"
)

var ErrKeyNotFound = fmt.Errorf("key not in database")

type Database interface {
	SaveAuth(ctx context.Context, key string, authentication messaging.Authentication, ttl time.Duration) error
	GetAuth(ctx context.Context, key string) (*messaging.Authentication, error)
	DeleteAuth(ctx context.Context, key string) (bool, error)
}
