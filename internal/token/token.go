package token

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	cloudeventprovider "github.com/eclipse-xfsc/cloud-event-provider"
	crypto "github.com/eclipse-xfsc/crypto-provider-service/pkg/messaging"
	"github.com/eclipse-xfsc/nats-message-library/common"
	"github.com/eclipse-xfsc/oid4-vci-authorization-bridge/v2/internal/config"
	"github.com/eclipse-xfsc/oid4-vci-authorization-bridge/v2/internal/health"
	"github.com/eclipse-xfsc/oid4-vci-authorization-bridge/v2/pkg/messaging"
	"github.com/eclipse-xfsc/oid4-vci-vp-library/model/credential"
	"github.com/google/uuid"
)

type Signer struct {
	client *cloudeventprovider.CloudEventProviderClient
	health *health.State
}

func NewSigner(ceConfig cloudeventprovider.Config, healthState *health.State) (*Signer, error) {
	client, err := cloudeventprovider.New(
		ceConfig,
		cloudeventprovider.ConnectionTypeReq,
		config.CurrentPreAuthBridgeConfig.OAuth.SignerTopic,
	)
	if err != nil {
		healthState.SetSigner(false)
		return nil, fmt.Errorf("failed to create signer request client: %w", err)
	}

	healthState.SetSigner(true)
	return &Signer{client: client, health: healthState}, nil
}

func (s *Signer) Close() {
	if s != nil && s.client != nil {
		s.client.Close()
	}
	if s != nil && s.health != nil {
		s.health.SetSigner(false)
	}
}

func (s *Signer) Sign(ctx context.Context, exp int64,
	storedAuth *messaging.Authentication,
	configuration *credential.CredentialConfigurationIdentifier,
	namespace, groupID, key, issuerKid, credentialEndpoint string) (string, error) {

	subject := storedAuth.Request.BuildSubject()
	p := make(map[string]interface{})
	p["nonce"] = storedAuth.Nonce
	p["aud"] = credentialEndpoint
	p["iat"] = time.Now().UTC().Unix()
	p["sub"] = subject
	p["exp"] = exp
	p["code"] = storedAuth.Code

	if configuration != nil {
		p["credentialConfiguration"] = configuration
	}

	pb, err := json.Marshal(p)
	if err != nil {
		return "", err
	}

	ph := make(map[string]interface{})
	ph["typ"] = "at+jwt"
	ph["kid"] = issuerKid

	pbh, err := json.Marshal(ph)
	if err != nil {
		return "", err
	}

	payload := map[string]interface{}{
		"tenant_id":  storedAuth.TenantId,
		"request_id": uuid.NewString(),
		"namespace":  namespace,
		"group":      groupID,
		"key":        key,
		"payload":    pb,
		"header":     pbh,
	}

	b, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}

	event, err := cloudeventprovider.NewEvent("preauth bridge", crypto.SignerServiceSignTokenType, b)
	if err != nil {
		return "", err
	}

	rep, err := s.client.RequestCtx(ctx, event)
	if err != nil {
		return "", err
	}

	if rep.Type() == crypto.SignerServiceSignTokenType {
		var tok crypto.CreateTokenReply
		if err = json.Unmarshal(rep.Data(), &tok); err != nil {
			return "", errors.Join(errors.New("cannot unmarshal event reply data"), err)
		}
		return string(tok.Token), nil
	}

	if rep.Type() == crypto.SignerServiceErrorType {
		var data common.Reply
		if err = json.Unmarshal(rep.Data(), &data); err != nil {
			return "", errors.Join(errors.New("cannot unmarshal event error reply data"), err)
		}
		return "", errors.Join(errors.New("error response from signer"),
			fmt.Errorf("status: %s id: %s msg: %s", data.Error.Status, data.Error.Id, data.Error.Msg),
		)
	}

	return "", fmt.Errorf("invalid response type received from signer. response type: %s", rep.Type())
}
