# Introduction

The pre authorization provides the new grant type for the OID4VCI flow to support issuing operations with the pre authorization flow. This bridge can be later configured in the open id configuration under the type urn:ietf:params:oauth:grant-type:pre-authorized_code which is defined in the [OID4VCI Spec](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#credential-offer-parameters) The service it self consists of a redis db which contains the temporary stored codes/pins and nonces for the requested codes which can be later exchange by an custom token endpoint to the authorization requestor.

# Flows

The pre authorization bridge will act as a proxy between the code requestor and the token issuer: 

```mermaid
sequenceDiagram
title Pre Authorization Flow
User ->> Issuing Service: Request Credential Link
Issuing Service ->> Pre Authorization Service: Request Code for Offering Link + TTL
Pre Authorization Service->> Pre Authorization Service: Create Code
Pre Authorization Service->> Redis: Stores Code in DB with TTL
Pre Authorization Service-->> User: Sends PIN (if required)
Pre Authorization Service->> Issuing Service: Return Code
Issuing Service->> Issuing Service: Create Offering
Issuing Service ->> User: Transmit Offering Link
User ->> Pre Authorization Service: Authorize with Code against /token endpoint
Pre Authorization Service->> Redis: Check Code/Remove Code
Pre Authorization Service->> OAuth Server: Client Credential Flow to Obtain Token
Pre Authorization Service->> User: Send Token
User->> Issuing Service: Use Token for Get Credential
Issuing Service->> OAuth Server: Check Token against Token Issuer
Issuing Service ->> User: Return Credential 

```

# Dependencies

- Nats
- Redis
- OAUTH 2.0 System (e.g. Keycloak or Hydra)


# Bootstrap

Pull either the docker image from harbor: 

```
docker pull node-654e3bca7fbeeed18f81d7c7.ps-xaas.io/ocm-wstack/pre-authorization-bridge:main
```

or use the docker compose file or [helm chart](./deployment/helm/). 


# Developer Information


Currently there are two possibilities for authentication:
1. only authentication code
2. authentication code and pin (two-factor)

every authentication have a configurable time-to-live(ttl)

## Configuration
````yaml
protocol: nats
nats:
  url: http://localhost:4222
  timeoutInSec: 10

logLevel: debug
servingPort: 3001
databaseUrl: redis://user:pass@localhost:6379/0
defaultTtlInMin: 30
oAuth:
  serverUrl: http://hydra:4444
  clientId: bridge
  clientSecret: secret
wellKnown:
  issuer: http://localhost:8080
  token_endpoint: http://localhost:8080/token
  grant_types_supported: urn:ietf:params:oauth:grant-type:pre-authorized_code
````

## Usage
Bridge expects cloudevent to trigger pre-authentication with following structure:
````go
type offerEvent struct {
    TwoFactor struct {
        Enabled          bool   `mapstructure:"enabled"`
        RecipientType    string `mapstructure:"recipientType"` //only when Enabled=true
        RecipientAddress string `mapstructure:"recipientAddress"` //only when Enabled=true
    } `mapstructure:"twoFactor"`
    Ttl time.Duration `mapstructure:"ttl"`
}
````

## Authorization Server
### hydra
````bash
hydra create client --endpoint http://localhost:4445/ --grant-type client_credentials --token-endpoint-auth-method client_secret_post
````

