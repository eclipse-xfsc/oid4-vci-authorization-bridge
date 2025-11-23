package messaging

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"time"

	"github.com/cloudevents/sdk-go/v2/event"
	ce "github.com/eclipse-xfsc/cloud-event-provider"
	ctxPkg "github.com/eclipse-xfsc/microservice-core-go/pkg/ctx"
	"github.com/eclipse-xfsc/nats-message-library/common"
	"github.com/sirupsen/logrus"
	"golang.org/x/sync/errgroup"

	"github.com/eclipse-xfsc/oid4-vci-authorization-bridge/v2/internal/config"
	"github.com/eclipse-xfsc/oid4-vci-authorization-bridge/v2/internal/security"
	"github.com/eclipse-xfsc/oid4-vci-authorization-bridge/v2/pkg/messaging"
)

type RecipientType string

type Recipient struct {
	Type    RecipientType
	Address string
}

func (r Recipient) Validate() error {
	if r.Type == "" {
		return fmt.Errorf("invalid or missing recipient type")
	}

	if r.Address == "" {
		return fmt.Errorf("invalid or missing recipient address")
	}

	return nil
}

const (
	didComm      RecipientType = "didComm"
	email        RecipientType = "email"
	didCommRegex               = "did:[a-z]+:[A-Za-z0-9]+"
	emailRegex                 = "^[\\w-\\.]+@([\\w-]+\\.)+[\\w-]{2,4}$"
)

type twoFactorOffer struct {
	Pin              string
	RecipientType    RecipientType
	RecipientAddress string
}

type offerEvent struct {
	TwoFactor struct {
		Enabled          bool          `mapstructure:"enabled"`
		RecipientType    RecipientType `mapstructure:"recipientType"`
		RecipientAddress string        `mapstructure:"recipientAddress"`
	} `mapstructure:"twoFactor"`
	Ttl time.Duration `mapstructure:"ttl" `
}

type didCommEvent struct {
	Subject        string `json:"subject"`
	DidCommAddress string `json:"didCommAddress"`
	Body           string `json:"body"`
}

type emailEvent struct {
	Subject      string `json:"subject"`
	EmailAddress string `json:"to-email"`
	Body         string `json:"body"`
}

type EventGateway struct {
	ceConfig           ce.Config
	secondFactorClient *ce.CloudEventProviderClient
	authHandler        security.AuthHandler
}

func NewEventGateway(ceConfig ce.Config, authHandler security.AuthHandler) EventGateway {
	return EventGateway{
		ceConfig:           ceConfig,
		secondFactorClient: nil,
		authHandler:        authHandler,
	}
}

// Listen starts the request handler by listening for incoming requests
func (e EventGateway) Listen(ctx context.Context) error {
	errGrp, ctx := errgroup.WithContext(ctx)

	errGrp.Go(func() error {
		return e.generateAuthorizationListener(ctx)
	})

	errGrp.Go(func() error {
		return e.validationListener(ctx)
	})

	return errGrp.Wait()
}

// Listen starts the request handler by listening for incoming requests
func (e EventGateway) generateAuthorizationListener(ctx context.Context) error {
	log := ctxPkg.GetLogger(ctx)

	repClient, err := ce.New(e.ceConfig, ce.ConnectionTypeRep, messaging.TopicGenerateAuthorization)
	if err != nil {
		panic(err)
	}
	defer repClient.Close()

	for {

		if ctx.Err() != nil {
			ctxPkg.GetLogger(ctx).Error(err, err.Error())
			return ctx.Err()
		}

		if err := repClient.ReplyCtx(ctx, e.GenerateAuthorizationHandler); err != nil {
			log.Error(err, "failed to Reply (via GenerateAuthorizationHandler)")
		}
	}
}

func (e EventGateway) secondFactorPublisher(ctx context.Context) *ce.CloudEventProviderClient {
	log := ctxPkg.GetLogger(ctx)
	if e.secondFactorClient == nil {
		client, err := ce.New(e.ceConfig, ce.ConnectionTypePub, config.CurrentPreAuthBridgeConfig.TwoFactorTopic)
		if err != nil {
			log.Error(err, "failed to create new client to publish two-factor event")
		}
		e.secondFactorClient = client
	}
	return e.secondFactorClient
}

func (e EventGateway) validationListener(ctx context.Context) error {
	offerClient, err := ce.New(e.ceConfig, ce.ConnectionTypeRep, messaging.TopicValidation)
	if err != nil {
		return err
	}

	for {

		if ctx.Err() != nil {
			ctxPkg.GetLogger(ctx).Error(err, err.Error())
			return ctx.Err()
		}

		if err := offerClient.ReplyCtx(ctx, e.validationHandler); err != nil {
			ctxPkg.GetLogger(ctx).Error(err, "Reply with offerHandler failed")
		}
	}
}

func (e EventGateway) validationHandler(ctx context.Context, ev event.Event) (*event.Event, error) {
	var req messaging.ValidateAuthenticationReq
	if err := json.Unmarshal(ev.Data(), &req); err != nil {
		return nil, err
	}

	valid, nonce, auth, err := e.authHandler.ValidateAuth(ctx, req.Params.Key)
	if err != nil {
		return nil, err
	}

	rep := messaging.ValidateAuthenticationRep{
		Reply: common.Reply{
			TenantId:  auth.TenantId,
			RequestId: auth.RequestId,
			GroupId:   auth.GroupId,
			Error:     nil,
		},
		Valid:                    valid,
		Nonce:                    nonce,
		CredentialConfigurations: auth.CredentialConfigurations,
	}

	jsonRepl, err := json.Marshal(rep)
	if err != nil {
		return nil, err
	}

	reply, err := ce.NewEvent(messaging.SourcePreAuthBridge, ev.Type(), jsonRepl)
	if err != nil {
		return nil, err
	}

	return &reply, nil
}

func (e EventGateway) GenerateAuthorizationHandler(ctx context.Context, event event.Event) (*event.Event, error) {
	log := ctxPkg.GetLogger(ctx)
	log.Debug("received offer event", "event", event)

	var req messaging.GenerateAuthorizationReq
	if err := json.Unmarshal(event.Data(), &req); err != nil {
		log.Error(err, "failed to unmarshal event data")
		return nil, err
	}

	ttl := time.Duration(config.CurrentPreAuthBridgeConfig.DefaultTtlInMin) * time.Minute

	nonce := req.Nonce

	if nonce == "" {
		nonce, _ = e.authHandler.GenerateCode()
	}

	newAuth, err := e.authHandler.Generate(ctx, req.Request, req.TwoFactor.Enabled, ttl, nonce, req.CredentialConfigurations, req.Claims)
	if err != nil {
		err = fmt.Errorf("error occured while generate new authentication: %w", err)
		log.Error(err, "failed to generate new auth")
		return nil, err
	}

	reply := messaging.GenerateAuthorizationRep{
		Reply: common.Reply{
			TenantId:  req.TenantId,
			RequestId: req.RequestId,
			GroupId:   req.GroupId,
		},
		Authentication: messaging.Authentication{
			Request:                  req.Request,
			Code:                     newAuth.Code,
			Nonce:                    nonce,
			CredentialConfigurations: req.CredentialConfigurations,
			TxCode:                   newAuth.TxCode,
			ExpiresAt:                newAuth.ExpiresAt,
			Claims:                   newAuth.Claims,
		},
	}
	logrus.Info("Code: " + newAuth.Code + " " + newAuth.Pin)
	replyData, err := json.Marshal(reply)
	if err != nil {
		log.Error(err, "failed to marshal reply data")
		return nil, err
	}

	replyEvent, err := ce.NewEvent(messaging.SourcePreAuthBridge, messaging.EventTypeGenerateAuthorization, replyData)
	if err != nil {
		log.Error(err, "failed to create NewEvent")
		return nil, err
	}

	if req.TwoFactor.Enabled {
		twoFactor := req.TwoFactor

		isValid, err := e.checkTwoFactor(Recipient{
			Type:    RecipientType(twoFactor.RecipientType),
			Address: twoFactor.RecipientAddress,
		})
		if err != nil {
			log.Error(err, "failed to checkTwoFactor")
			return nil, err
		}

		if !isValid {
			log.Error(err, fmt.Sprintf("recipientAddress %s does not match recipientType %s", twoFactor.RecipientAddress, twoFactor.RecipientType))
			return nil, err
		}

		offer := twoFactorOffer{
			Pin:              newAuth.Pin,
			RecipientType:    RecipientType(twoFactor.RecipientType),
			RecipientAddress: twoFactor.RecipientAddress,
		}

		if err := e.processTwoFactor(ctx, offer); err != nil {
			log.Error(err, "error occurred while processing two-factor offer")
			return nil, err
		}
	}

	log.Debug("reply with authCode", "authCode", newAuth.Code)

	return &replyEvent, nil
}

func (e EventGateway) processTwoFactor(ctx context.Context, offer twoFactorOffer) error {
	log := ctxPkg.GetLogger(ctx)

	var eventType string
	var data json.RawMessage
	var err error
	switch offer.RecipientType {
	case didComm:
		eventType = "didcomm.pin.v1"
		data, err = json.Marshal(didCommEvent{
			Subject:        "two-factor.pin",
			DidCommAddress: offer.RecipientAddress,
			Body:           offer.Pin,
		})
	case email:
		eventType = "email.pin.v1"
		data, err = json.Marshal(emailEvent{
			Subject:      "two-factor.pin",
			EmailAddress: offer.RecipientAddress,
			Body:         offer.Pin,
		})

	default:
		return fmt.Errorf("recipientType %s is not valid", offer.RecipientType)
	}

	if err != nil {
		log.Error(err, "error while creating twoFactorEvent for recipientAddress", "recipient", offer.RecipientAddress)
		return err
	}

	newEvent, err := ce.NewEvent("preauthbridge/handleOffer", eventType, data)
	if err != nil {
		log.Error(err, "error while creating twoFactorOffer for twoFactorOffer publishing", "event", newEvent)
	}

	log.Debug("send request with pinCode", "pin", offer.Pin)

	if err = e.secondFactorPublisher(ctx).PubCtx(ctx, newEvent); err != nil {
		log.Error(err, "error while publishing pin event", "event", newEvent)
		return fmt.Errorf("error while publish pin event %v for two-factor: %w", newEvent, err)
	}

	return nil
}

func (e EventGateway) checkTwoFactor(recipient Recipient) (bool, error) {
	if err := recipient.Validate(); err != nil {
		return false, err
	}

	var match bool
	var err error
	switch recipient.Type {
	case didComm:
		match, err = regexp.Match(didCommRegex, []byte(recipient.Address))
	case email:
		match, err = regexp.Match(emailRegex, []byte(recipient.Address))
	default:
		return false, fmt.Errorf("recipientType %s is not valid", recipient.Type)
	}

	if err != nil {
		return false, fmt.Errorf("unexpected error while checking regex: %w", err)
	}

	return match, nil
}
