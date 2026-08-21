package health

import (
	"context"
	"sync"
)

type RedisChecker interface {
	Health(ctx context.Context) error
}

type State struct {
	redis RedisChecker

	mu                    sync.RWMutex
	generateAuthorization bool
	validation            bool
	signer                bool
}

type ComponentStatus struct {
	Status string `json:"status"`
	Error  string `json:"error,omitempty"`
}

type MessagingStatus struct {
	GenerateAuthorization ComponentStatus `json:"generateAuthorization"`
	Validation            ComponentStatus `json:"validation"`
	Signer                ComponentStatus `json:"signer"`
}

type Status struct {
	Status    string          `json:"status"`
	Redis     ComponentStatus `json:"redis"`
	Messaging MessagingStatus `json:"messaging"`
}

func New(redis RedisChecker) *State {
	return &State{redis: redis}
}

func (s *State) SetGenerateAuthorization(healthy bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.generateAuthorization = healthy
}

func (s *State) SetValidation(healthy bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.validation = healthy
}

func (s *State) SetSigner(healthy bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.signer = healthy
}

func component(healthy bool) ComponentStatus {
	if healthy {
		return ComponentStatus{Status: "healthy"}
	}
	return ComponentStatus{Status: "unhealthy"}
}

func (s *State) Check(ctx context.Context) Status {
	s.mu.RLock()
	generateAuthorization := s.generateAuthorization
	validation := s.validation
	signer := s.signer
	s.mu.RUnlock()

	status := Status{
		Status: "healthy",
		Messaging: MessagingStatus{
			GenerateAuthorization: component(generateAuthorization),
			Validation:            component(validation),
			Signer:                component(signer),
		},
	}

	if err := s.redis.Health(ctx); err != nil {
		status.Redis = ComponentStatus{Status: "unhealthy", Error: err.Error()}
		status.Status = "unhealthy"
	} else {
		status.Redis = ComponentStatus{Status: "healthy"}
	}

	if !generateAuthorization || !validation || !signer {
		status.Status = "unhealthy"
	}

	return status
}
