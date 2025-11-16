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
	"github.com/eclipse-xfsc/oid4-vci-authorization-bridge/internal/config"
	"github.com/eclipse-xfsc/oid4-vci-authorization-bridge/pkg/messaging"
	"github.com/google/uuid"
)

func New(ctx context.Context, exp int64, storedAuth *messaging.Authentication) (string, error) {

	subject := storedAuth.Request.BuildSubject()

	client, err := cloudeventprovider.New(cloudeventprovider.Config{
		Protocol: cloudeventprovider.ProtocolTypeNats,
		Settings: cloudeventprovider.NatsConfig{
			Url:          config.CurrentPreAuthBridgeConfig.Nats.Url,
			QueueGroup:   config.CurrentPreAuthBridgeConfig.Nats.QueueGroup,
			TimeoutInSec: config.CurrentPreAuthBridgeConfig.Nats.TimeoutInSec,
		},
	}, cloudeventprovider.ConnectionTypeReq, config.CurrentPreAuthBridgeConfig.OAuth.SignerTopic)

	if err != nil {
		return "", err
	}

	var p = make(map[string]interface{})
	p["nonce"] = storedAuth.Nonce
	p["aud"] = config.CurrentPreAuthBridgeConfig.OAuth.CredentialEndpoint
	p["iat"] = time.Now().UTC().Unix()
	p["sub"] = subject
	p["exp"] = exp

	pb, err := json.Marshal(p)

	if err != nil {
		return "", err
	}

	var ph = make(map[string]interface{})
	ph["typ"] = "at+jwt"
	ph["kid"] = config.CurrentPreAuthBridgeConfig.OAuth.Issuer

	pbh, err := json.Marshal(ph)

	if err != nil {
		return "", err
	}

	payload := map[string]interface{}{
		"tenant_id":  storedAuth.TenantId,
		"request_id": uuid.NewString(),
		"namespace":  storedAuth.TenantId,
		"group":      storedAuth.GroupId,
		"key":        config.CurrentPreAuthBridgeConfig.OAuth.Key,
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

	rep, err := client.RequestCtx(context.Background(), event)

	if err != nil {
		return "", err
	}
	if rep.Type() == crypto.SignerServiceSignTokenType {
		var tok crypto.CreateTokenReply
		err = json.Unmarshal(rep.Data(), &tok)
		if err != nil {
			return "", errors.Join(errors.New("cannot unmarshal event reply data"), err)
		}
		return string(tok.Token), err
	} else if rep.Type() == crypto.SignerServiceErrorType {
		var data common.Reply
		err = json.Unmarshal(rep.Data(), &data)
		if err != nil {
			return "", errors.Join(errors.New("cannot unmarshal event error reply data"), err)
		}
		return "", errors.Join(errors.New("error response from signer"),
			fmt.Errorf("status: %s id: %s msg: %s", data.Error.Status, data.Error.Id, data.Error.Msg),
		)
	} else {
		return "", fmt.Errorf("invalid response type received from signer. response type: %s", rep.Type())
	}
}
