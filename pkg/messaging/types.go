package messaging

import (
	"time"

	"github.com/eclipse-xfsc/nats-message-library/common"
	"github.com/eclipse-xfsc/oid4-vci-vp-library/model/credential"
	"github.com/eclipse-xfsc/oid4-vci-vp-library/model/oauth"
)

const SourcePreAuthBridge = "preauthbridge"

const (
	TopicGenerateAuthorization     = "auth.authorization.generate"
	EventTypeGenerateAuthorization = "auth.authorization.generate"
)

type GenerateAuthorizationReq struct {
	common.Request
	TwoFactor                TwoFactor                                      `json:"twoFactor"`
	CredentialConfigurations []credential.CredentialConfigurationIdentifier `json:"credential_configurations"`
	Nonce                    string                                         `json:"nonce"`
	Claims                   []oauth.Claim                                  `json:"claims"`
}

type TwoFactor struct {
	Enabled          bool   `json:"enabled"`
	RecipientType    string `json:"recipientType"`
	RecipientAddress string `json:"recipientAddress"`
}

type GenerateAuthorizationRep struct {
	common.Reply
	Authentication
}

type Authentication struct {
	common.Request
	Token                    string                                         `json:"token"`
	Code                     string                                         `json:"code"`
	Nonce                    string                                         `json:"nonce"`
	Pin                      string                                         `json:"pin"`
	ExpiresAt                time.Time                                      `json:"expires_at"`
	CredentialConfigurations []credential.CredentialConfigurationIdentifier `json:"credential_configurations"`
	TxCode                   *credential.TxCode                             `json:"tx_code"`
	Claims                   []oauth.Claim                                  `json:"claims"`
}

const (
	TopicValidation     = "auth.authorization.validate"
	EventTypeValidation = "auth.authorization.validate.v1"
)

type ValidateAuthenticationReq struct {
	common.Request
	Params ValidateAuthenticationReqParams
}

type ValidateAuthenticationReqParams struct {
	Key string `json:"key"`
}

type ValidateAuthenticationRep struct {
	common.Reply
	Valid                    bool                                           `json:"valid"`
	Nonce                    string                                         `json:"nonce"`
	CredentialConfigurations []credential.CredentialConfigurationIdentifier `json:"credential_configurations"`
}
