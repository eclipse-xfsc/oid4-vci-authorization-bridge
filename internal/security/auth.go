package security

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/eclipse-xfsc/nats-message-library/common"
	"github.com/eclipse-xfsc/oid4-vci-authorization-bridge/v2/pkg/messaging"
	"github.com/eclipse-xfsc/oid4-vci-vp-library/model/credential"

	"github.com/eclipse-xfsc/oid4-vci-authorization-bridge/v2/internal/database"
	"github.com/eclipse-xfsc/oid4-vci-authorization-bridge/v2/pkg/generator"
)

const codeLength = 20
const pinLength = 6

type AuthHandler struct {
	db database.Database
}

func NewAuthHandler(dbConnection database.Database) *AuthHandler {
	return &AuthHandler{db: dbConnection}
}

func (a *AuthHandler) Generate(ctx context.Context, req common.Request, withPin bool, ttl time.Duration, nonce string, credential_configurations []credential.CredentialConfigurationIdentifier) (*messaging.Authentication, error) {
	code, err := a.GenerateCode()
	if err != nil {
		return nil, fmt.Errorf("error occured while generating new authCode: %w", err)
	}

	newAuth := messaging.Authentication{
		Request:                  req,
		Code:                     code,
		ExpiresAt:                time.Now().Add(ttl),
		Nonce:                    nonce,
		CredentialConfigurations: credential_configurations,
	}

	var pin string
	if withPin {
		pin, err = a.GeneratePin()
		if err != nil {
			return nil, fmt.Errorf("error occured while generating new authPin: %w", err)
		}

		newAuth.Pin = pin
		newAuth.TxCode = &credential.TxCode{
			InputMode:   "numeric",
			Length:      pinLength,
			Description: "Type in the code which where sent to the selected channel.",
		}
	}

	if err := a.db.SaveAuth(ctx, newAuth.Code, newAuth, ttl); err != nil {
		return nil, fmt.Errorf("error occured while saving auth to database: %w", err)
	}

	return &newAuth, nil
}

func (a *AuthHandler) GetAuth(ctx context.Context, key string) (*messaging.Authentication, error) {
	storedAuth, err := a.db.GetAuth(ctx, key)
	if err != nil {
		if errors.Is(err, database.ErrKeyNotFound) {
			// key does not exist in the database anymore -> ttl is over
			return nil, fmt.Errorf("not found")
		}

		return nil, err
	}

	return storedAuth, nil
}

func (a *AuthHandler) ValidateAuth(ctx context.Context, key string) (valid bool, nonce string, auth *messaging.Authentication, err error) {
	auth, err = a.db.GetAuth(ctx, key)

	if err != nil || auth == nil {
		return false, "", nil, err
	}

	b, err := a.db.DeleteAuth(ctx, key)

	if err != nil {
		return false, "", nil, err
	}

	return auth != nil && b, auth.Nonce, auth, nil
}

func (a *AuthHandler) StoreAuth(ctx context.Context, key string, auth messaging.Authentication) error {
	return a.db.SaveAuth(ctx, key, auth, auth.ExpiresAt.Sub(time.Now()))
}

func (a *AuthHandler) Delete(ctx context.Context, key string) (bool, error) {
	if _, err := a.db.DeleteAuth(ctx, key); err != nil {
		if errors.Is(err, database.ErrKeyNotFound) {
			// key does not exist in the database anymore -> ttl is over
			return false, nil
		}

		return false, fmt.Errorf("error occured while deleting pin from database for key %s: %w", key, err)
	}

	return true, nil
}

func (a *AuthHandler) GenerateCode() (string, error) {
	return generator.RandomCode(codeLength, generator.Characters, generator.Numbers)
}

func (a *AuthHandler) GeneratePin() (string, error) {
	return generator.RandomCode(pinLength, generator.Numbers)
}
