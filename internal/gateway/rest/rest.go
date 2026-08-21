package rest

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"

	"github.com/eclipse-xfsc/oid4-vci-authorization-bridge/v2/internal/config"
	"github.com/eclipse-xfsc/oid4-vci-authorization-bridge/v2/internal/health"
	"github.com/eclipse-xfsc/oid4-vci-authorization-bridge/v2/internal/security"
	"github.com/eclipse-xfsc/oid4-vci-authorization-bridge/v2/internal/token"
	"github.com/eclipse-xfsc/oid4-vci-vp-library/model/credential"
	"github.com/eclipse-xfsc/oid4-vci-vp-library/model/oauth"
	"github.com/gofiber/fiber/v2"
	"github.com/sirupsen/logrus"
)

type API struct {
	fbr         *fiber.App
	authHandler security.AuthHandler
	signer      *token.Signer
	health      *health.State
}

func NewRestApi(authHandler security.AuthHandler, signer *token.Signer, healthState *health.State) API {
	api := API{authHandler: authHandler, signer: signer, health: healthState}

	app := fiber.New()
	app.Post("/token", api.GetTokenHandler)
	app.Get("/.well-known/openid-configuration", api.GetWellKnownHandler)
	app.Get("/.well-known/jwks.json", api.GetJwksHandler)
	app.Get("/health", api.HealthCheckHandler)
	app.Head("/health", api.HealthCheckHandler)
	api.fbr = app
	return api
}

func (a API) Start(iface string, port int) error {
	logrus.Info("start serving rest endpoints!")
	return a.fbr.Listen(fmt.Sprintf("%s:%d", iface, port))
}

func (a API) Shutdown() error { return a.fbr.Shutdown() }

func (a API) HealthCheckHandler(c *fiber.Ctx) error {
	ctx, cancel := context.WithTimeout(c.UserContext(), 2*time.Second)
	defer cancel()

	status := a.health.Check(ctx)
	if status.Status != "healthy" {
		logrus.WithFields(logrus.Fields{
			"redis":                 status.Redis.Status,
			"redis_error":           status.Redis.Error,
			"generateAuthorization": status.Messaging.GenerateAuthorization.Status,
			"validation":            status.Messaging.Validation.Status,
			"signer":                status.Messaging.Signer.Status,
		}).Error("authorization bridge health check failed")
		return c.Status(fiber.StatusServiceUnavailable).JSON(status)
	}
	return c.Status(fiber.StatusOK).JSON(status)
}

func (a API) GetWellKnownHandler(c *fiber.Ctx) error {
	wellKnown := config.CurrentPreAuthBridgeConfig.WellKnown
	if value := c.Get("x-issuer"); value != "" {
		wellKnown.Issuer = value
	}
	if value := c.Get("x-jwks-url"); value != "" {
		wellKnown.Jwks = value
	}
	if value := c.Get("x-tokenendpoint"); value != "" {
		wellKnown.TokenEndpoint = value
	}
	return c.JSON(wellKnown)
}

func (a API) GetJwksHandler(c *fiber.Ctx) error {
	jwksURL := config.CurrentPreAuthBridgeConfig.OAuth.SignerJwksUrl
	req, err := http.NewRequest(http.MethodGet, jwksURL, nil)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": err.Error()})
	}

	namespace := config.CurrentPreAuthBridgeConfig.OAuth.Namespace
	if value := c.Get("x-namespace"); value != "" {
		namespace = value
	}
	group := config.CurrentPreAuthBridgeConfig.OAuth.GroupId
	if value := c.Get("x-group"); value != "" {
		group = value
	}
	engine := config.CurrentPreAuthBridgeConfig.OAuth.Engine
	if value := c.Get("x-engine"); value != "" {
		engine = value
	}

	req.Header.Set("x-namespace", namespace)
	req.Header.Set("x-group", group)
	req.Header.Set("x-engine", engine)
	resp, err := (&http.Client{}).Do(req)
	if err != nil {
		return c.Status(fiber.StatusBadGateway).JSON(fiber.Map{"error": "unable to reach JWKS upstream"})
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "failed to read JWKS response"})
	}
	return c.Status(resp.StatusCode).Send(body)
}

func (a API) GetTokenHandler(c *fiber.Ctx) error {
	invalidErrorResponse := map[string]string{"error": "invalid_request"}

	namespace := config.CurrentPreAuthBridgeConfig.OAuth.Namespace
	if value := c.Get("x-namespace"); value != "" {
		namespace = value
	}
	group := config.CurrentPreAuthBridgeConfig.OAuth.GroupId
	if value := c.Get("x-group"); value != "" {
		group = value
	}
	key := config.CurrentPreAuthBridgeConfig.OAuth.Key
	if value := c.Get("x-key"); value != "" {
		key = value
	}
	issuerKid := config.CurrentPreAuthBridgeConfig.OAuth.IssuerKid
	if value := c.Get("x-issuerKid"); value != "" {
		issuerKid = value
	}
	credentialEndpoint := config.CurrentPreAuthBridgeConfig.OAuth.CredentialEndpoint
	if value := c.Get("x-credentialendpoint"); value != "" {
		credentialEndpoint = value
	}

	code := c.FormValue("pre-authorized_code")
	pin := c.FormValue("tx_code")
	authorizationDetails := c.FormValue("authorization_details")
	logrus.Info("Code " + code + " Pin: " + pin + " authorization Details:" + authorizationDetails)

	storedAuth, err := a.authHandler.GetAuth(c.UserContext(), code)
	if err != nil {
		logrus.Error(fiber.NewError(fiber.StatusUnauthorized, "invalid auth code specified"))
		return c.Status(fiber.StatusBadRequest).JSON(invalidErrorResponse)
	}
	if storedAuth.Pin != pin {
		logrus.Error(fiber.NewError(fiber.StatusUnauthorized, "authentication code and pin are not matching"))
		return c.Status(fiber.StatusBadRequest).JSON(invalidErrorResponse)
	}
	if storedAuth.ExpiresAt.Before(time.Now()) {
		logrus.Error(fiber.NewError(fiber.StatusUnauthorized, "authentication expired"))
		return c.Status(fiber.StatusBadRequest).JSON(invalidErrorResponse)
	}
	if _, err := a.authHandler.Delete(c.UserContext(), code); err != nil {
		logrus.Errorf("error occured while deleting authentication code from database: %v", err)
		return c.Status(fiber.StatusBadRequest).JSON(invalidErrorResponse)
	}

	exp := storedAuth.ExpiresAt.Sub(time.Now())
	tokenResp := oauth.Token{
		TokenType:       "Bearer",
		ExpiresIn:       int64(exp.Seconds()),
		CNonce:          storedAuth.Nonce,
		CNonceExpiresIn: int64(exp.Seconds()),
	}

	var configuration *credential.CredentialConfigurationIdentifier
	if authorizationDetails != "" {
		decoded, err := url.QueryUnescape(authorizationDetails)
		if err != nil {
			logrus.Error(err)
			return c.Status(fiber.StatusBadRequest).JSON(invalidErrorResponse)
		}
		var details oauth.AuthorizationDetails
		if err := json.Unmarshal([]byte(decoded), &details); err != nil {
			logrus.Error(err)
			return c.Status(fiber.StatusBadRequest).JSON(invalidErrorResponse)
		}
		found := false
		index := 0
		for i, cfg := range storedAuth.CredentialConfigurations {
			if cfg.Id == details.CredentialConfigurationID {
				found = true
				index = i
				break
			}
		}
		if !found || !IsSubset(storedAuth.CredentialConfigurations[index].CredentialIdentifier, details.CredentialIdentifiers) {
			logrus.Error("credential definition matches not to the request")
			return c.Status(fiber.StatusBadRequest).JSON(invalidErrorResponse)
		}
		tokenResp.AuthorizationDetails = &oauth.AuthorizationDetails{
			Type: "openid_credential", CredentialConfigurationID: details.CredentialConfigurationID,
			CredentialIdentifiers: details.CredentialIdentifiers, Claims: details.Claims,
		}
		configuration = &storedAuth.CredentialConfigurations[index]
	} else if len(storedAuth.CredentialConfigurations) == 1 {
		tokenResp.AuthorizationDetails = &oauth.AuthorizationDetails{
			Type: "openid_credential", CredentialConfigurationID: storedAuth.CredentialConfigurations[0].Id,
			CredentialIdentifiers: storedAuth.CredentialConfigurations[0].CredentialIdentifier, Claims: storedAuth.Claims,
		}
		configuration = &storedAuth.CredentialConfigurations[0]
	}

	newToken, err := a.signer.Sign(c.UserContext(), storedAuth.ExpiresAt.Unix(), storedAuth, configuration,
		namespace, group, key, issuerKid, credentialEndpoint)
	if err != nil || newToken == "" {
		logrus.Errorf("error occured while retrieving token from authentication server: %v", err)
		return c.Status(fiber.StatusBadRequest).JSON(invalidErrorResponse)
	}

	ttl := time.Duration(config.CurrentPreAuthBridgeConfig.DefaultTtlInMin) * time.Minute
	storedAuth.Token = newToken
	storedAuth.ExpiresAt = time.Now().Add(ttl)
	if err := a.authHandler.StoreAuth(c.UserContext(), newToken, *storedAuth); err != nil {
		logrus.Errorf("failed to store updated auth to db: %v", err)
		return c.Status(fiber.StatusBadRequest).JSON(invalidErrorResponse)
	}

	tokenResp.AccessToken = newToken
	return c.JSON(tokenResp)
}

func IsSubset(big, small []string) bool {
	set := make(map[string]struct{}, len(big))
	for _, v := range big {
		set[v] = struct{}{}
	}
	for _, v := range small {
		if _, exists := set[v]; !exists {
			return false
		}
	}
	return true
}
