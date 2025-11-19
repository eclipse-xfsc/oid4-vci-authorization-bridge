package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	ce "github.com/eclipse-xfsc/cloud-event-provider"
	"github.com/eclipse-xfsc/nats-message-library/common"
	"github.com/eclipse-xfsc/oid4-vci-vp-library/model/credential"
	"github.com/nats-io/nats.go"
)

const (
	natsURL       = "nats://localhost:4222"
	topicGenerate = "auth.authorization.generate"
	topicValidate = "auth.authorization.validate"
	tokenEndpoint = "http://localhost:8081/token"
)

// Request structs (minimal)
type GenerateAuthorizationReq struct {
	TenantId                 string                    `json:"tenant_Id"`
	RequestId                string                    `json:"request_Id"`
	GroupId                  string                    `json:"group_Id"`
	Nonce                    string                    `json:"nonce"`
	Request                  string                    `json:"request"`
	CredentialConfigurations []CredentialConfiguration `json:"credential_configurations"`
	TwoFactor                struct {
		Enabled          bool   `json:"enabled"`
		RecipientType    string `json:"recipientType"`
		RecipientAddress string `json:"recipientAddress"`
	} `json:"twoFactor"`
}

type GenerateAuthorizationRep struct {
	common.Reply
	Authentication
}

type CredentialConfiguration struct {
	Id                   string   `json:"configuration_id"`
	CredentialIdentifier []string `json:"credential_identifier"`
}

type Authentication struct {
	common.Request
	Token                    string                    `json:"token"`
	Code                     string                    `json:"code"`
	Nonce                    string                    `json:"nonce"`
	Pin                      string                    `json:"pin"`
	ExpiresAt                time.Time                 `json:"expires_at"`
	CredentialConfigurations []CredentialConfiguration `json:"credential_configurations"`
	TxCode                   *credential.TxCode        `json:"tx_code"`
}

type ValidateAuthenticationReq struct {
	Params struct {
		Key string `json:"key"`
	} `json:"params"`
}

type ValidateAuthenticationRep struct {
	Valid bool `json:"valid"`
}

func main() {
	ctx := context.Background()

	//------------------------------------------------------------
	// 1) NATS Request: Generate Authorization Code
	//------------------------------------------------------------
	fmt.Println("📨 requesting authorization code via NATS...")

	genReq := GenerateAuthorizationReq{
		TenantId:  "tenant_space",
		RequestId: "req-001",
		Request:   "sample-oauth-request",
		CredentialConfigurations: []CredentialConfiguration{
			CredentialConfiguration{
				Id: "conf-123",
				CredentialIdentifier: []string{
					"cred-abc",
				},
			},
		},
	}
	genReq.TwoFactor.Enabled = false // simplify demo

	var authResp GenerateAuthorizationRep

	if err := natsCERequest(ctx, topicGenerate, genReq, &authResp); err != nil {
		panic(err)
	}

	code := authResp.Authentication.Code
	nonce := authResp.Authentication.Nonce

	fmt.Printf("✅ received auth code: %s (nonce=%s)\n", code, nonce)

	//------------------------------------------------------------
	// 2) REST Token Request
	//------------------------------------------------------------
	fmt.Println("🌐 requesting token via REST...")

	token, err := requestToken(code)
	if err != nil {
		panic(err)
	}

	fmt.Println("🔑 received token:", token)

	//------------------------------------------------------------
	// 3) NATS Validation Request
	//------------------------------------------------------------
	fmt.Println("🔍 validating token via NATS...")

	validReq := ValidateAuthenticationReq{}
	validReq.Params.Key = token["access_token"].(string) // validation checks the code/key

	validResp := ValidateAuthenticationRep{}

	if err := natsCERequest(ctx, topicValidate, validReq, &validResp); err != nil {
		panic(err)
	}

	fmt.Println("🔎 validation result:", validResp.Valid)
}

// -------------------------------------------------------------------
// NATS CloudEvent Request Helper
// -------------------------------------------------------------------
func natsCERequest(ctx context.Context, subject string, data any, out any) error {
	nc, err := nats.Connect(natsURL)
	if err != nil {
		return err
	}
	defer nc.Drain()

	reqBytes, _ := json.Marshal(data)
	evt, err := ce.NewEvent("test-client", "test.v1", reqBytes)
	if err != nil {
		return err
	}
	rawEvt, _ := evt.MarshalJSON()

	msg, err := nc.Request(subject, rawEvt, 10*time.Second)
	if err != nil {
		return err
	}

	// decode CloudEvent
	var respEvent map[string]any
	if err := json.Unmarshal(msg.Data, &respEvent); err != nil {
		return err
	}

	// extract .data

	dataBytes, _ := json.Marshal(respEvent["data"])
	o := json.Unmarshal(dataBytes, out)
	return o
}

// -------------------------------------------------------------------
// Token Request (REST / OAuth Style)
// -------------------------------------------------------------------
func requestToken(code string) (map[string]interface{}, error) {
	body := fmt.Sprintf("grant_type=urn:ietf:params:oauth:grant-type:pre-authorized_code&pre-authorized_code=%s", code)
	req, _ := http.NewRequest("POST", tokenEndpoint, bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()

	b, _ := io.ReadAll(res.Body)
	var ret map[string]interface{}
	json.Unmarshal(b, &ret)
	return ret, nil
}
