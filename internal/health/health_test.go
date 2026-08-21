package health

import (
	"context"
	"errors"
	"testing"
)

type fakeRedis struct{ err error }

func (f fakeRedis) Health(context.Context) error { return f.err }

func TestCheckHealthy(t *testing.T) {
	state := New(fakeRedis{})
	state.SetGenerateAuthorization(true)
	state.SetValidation(true)
	state.SetSigner(true)

	got := state.Check(context.Background())
	if got.Status != "healthy" {
		t.Fatalf("expected healthy, got %s", got.Status)
	}
}

func TestCheckRedisFailure(t *testing.T) {
	state := New(fakeRedis{err: errors.New("NOPERM")})
	state.SetGenerateAuthorization(true)
	state.SetValidation(true)
	state.SetSigner(true)

	got := state.Check(context.Background())
	if got.Status != "unhealthy" {
		t.Fatalf("expected unhealthy, got %s", got.Status)
	}
	if got.Redis.Error != "NOPERM" {
		t.Fatalf("expected redis error, got %q", got.Redis.Error)
	}
}

func TestCheckResponderFailure(t *testing.T) {
	state := New(fakeRedis{})
	state.SetGenerateAuthorization(true)
	state.SetValidation(false)
	state.SetSigner(true)

	got := state.Check(context.Background())
	if got.Status != "unhealthy" {
		t.Fatalf("expected unhealthy, got %s", got.Status)
	}
	if got.Messaging.Validation.Status != "unhealthy" {
		t.Fatalf("expected validation responder unhealthy")
	}
}
