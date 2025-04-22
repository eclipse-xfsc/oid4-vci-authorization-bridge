package messaging

import (
	"time"

	"github.com/eclipse-xfsc/nats-message-library/common"
	"github.com/eclipse-xfsc/oid4-vci-vp-library/model/credential"
)

const SourcePreAuthBridge = "preauthbridge"

const (
	TopicGenerateAuthorization     = "auth.authorization.generate"
	EventTypeGenerateAuthorization = "auth.authorization.generate"
)

type GenerateAuthorizationReq struct {
	common.Request
	TwoFactor                 TwoFactor `json:"twoFactor"`
	CredentialConfigurationId string    `json:"credential_configuration_id"`
	CredentialIdentifier      []string  `json:"credential_identifier"`
	Nonce                     string    `json:"nonce"`
}

type TwoFactor struct {
	Enabled          bool   `json:"enabled"`
	RecipientType    string `json:"recipientType"`
	RecipientAddress string `json:"recipientAddress"`
}

type GenerateAuthorizationRep struct {
	common.Reply
	*Authentication
}

type Authentication struct {
	Token                     string             `json:"token"`
	Code                      string             `json:"code"`
	Nonce                     string             `json:"nonce"`
	Pin                       string             `json:"pin"`
	ExpiresAt                 time.Time          `json:"expires_at"`
	CredentialConfigurationId string             `json:"credential_configuration_id"`
	CredentialIdentifier      []string           `json:"credential_identifier"`
	TxCode                    *credential.TxCode `json:"tx_code"`
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
	Valid                     bool     `json:"valid"`
	Nonce                     string   `json:"nonce"`
	CredentialConfigurationId *string  `json:"credential_configuration_id"`
	CredentialIdentifier      []string `json:"credential_identifier"`
}
