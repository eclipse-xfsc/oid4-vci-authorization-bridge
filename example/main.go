package main

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"time"

	cloudeventprovider "github.com/eclipse-xfsc/cloud-event-provider"
	"github.com/eclipse-xfsc/nats-message-library/common"
	"github.com/eclipse-xfsc/oid4-vci-authorization-bridge/v2/pkg/messaging"
	"github.com/google/uuid"
)

func main() {
	client, _ := cloudeventprovider.New(
		cloudeventprovider.Config{Protocol: cloudeventprovider.ProtocolTypeNats, Settings: cloudeventprovider.NatsConfig{
			Url:          "nats://localhost:4222",
			TimeoutInSec: time.Minute,
		}},
		cloudeventprovider.ConnectionTypeReq,
		messaging.TopicGenerateAuthorization,
	)
	reader := bufio.NewReader(os.Stdin)
	for {
		var req = messaging.GenerateAuthorizationReq{
			Request: common.Request{
				TenantId:  "tenant_space",
				RequestId: uuid.NewString(),
			},
			TwoFactor: messaging.TwoFactor{
				Enabled: false,
			},
			CredentialConfigurations: []messaging.CredentialConfiguration{
				messaging.CredentialConfiguration{
					Id:                   "DeveloperCredential",
					CredentialIdentifier: []string{"my-identifier"},
				},
			},
		}

		b, _ := json.Marshal(req)

		testEvent, _ := cloudeventprovider.NewEvent("test-issuer", messaging.EventTypeGenerateAuthorization, b)

		ev, _ := client.RequestCtx(context.Background(), testEvent)

		var rep messaging.GenerateAuthorizationRep

		json.Unmarshal(ev.Data(), &rep)

		fmt.Println(rep)
		reader.ReadString('\n')
	}
}
