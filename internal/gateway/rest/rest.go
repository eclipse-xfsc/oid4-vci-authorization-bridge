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
	"github.com/eclipse-xfsc/oid4-vci-authorization-bridge/v2/internal/security"
	"github.com/eclipse-xfsc/oid4-vci-authorization-bridge/v2/internal/token"
	"github.com/eclipse-xfsc/oid4-vci-vp-library/model/credential"
	"github.com/eclipse-xfsc/oid4-vci-vp-library/model/oauth"
	"github.com/gofiber/fiber/v2"
	"github.com/sirupsen/logrus"
	log "github.com/sirupsen/logrus"
)

type API struct {
	fbr         *fiber.App
	authHandler security.AuthHandler
}

func NewRestApi(authHandler security.AuthHandler) API {
	api := API{
		authHandler: authHandler,
	}

	app := fiber.New()
	app.Post("/token", api.GetTokenHandler)
	app.Get("/.well-known/openid-configuration", api.GetWellKnownHandler)
	app.Get("/.well-known/jwks.json", api.GetJwksHandler)
	app.Head("/health_check", api.HealthCheckHandler)

	api.fbr = app

	return api
}

func (a API) Start(iface string, port int) error {
	log.Info("start serving rest endpoints!")

	return a.fbr.Listen(fmt.Sprintf("%s:%d", iface, port))
}

func (a API) Shutdown() error {
	return a.fbr.Shutdown()
}

func (a API) HealthCheckHandler(c *fiber.Ctx) error {
	return c.SendStatus(fiber.StatusOK)
}

func (a API) GetWellKnownHandler(c *fiber.Ctx) error {
	return c.JSON(config.CurrentPreAuthBridgeConfig.WellKnown)
}

func (a API) GetJwksHandler(c *fiber.Ctx) error {
	jwksURL := config.CurrentPreAuthBridgeConfig.OAuth.SignerJwksUrl

	// HTTP Client erstellen
	req, err := http.NewRequest("GET", jwksURL, nil)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": err.Error(),
		})
	}

	// Header weitergeben
	req.Header.Set("x-namespace", config.CurrentPreAuthBridgeConfig.OAuth.Namespace)
	req.Header.Set("x-group", config.CurrentPreAuthBridgeConfig.OAuth.GroupId)

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return c.Status(fiber.StatusBadGateway).JSON(fiber.Map{
			"error": "unable to reach JWKS upstream",
		})
	}
	defer resp.Body.Close()

	// Response Body lesen
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "failed to read JWKS response",
		})
	}

	// Upstream-Status übernehmen und JWKS weiterreichen
	return c.Status(resp.StatusCode).Send(body)
}

func (a API) GetTokenHandler(c *fiber.Ctx) error {

	var InvalidErrorResponse = map[string]string{
		"error": "invalid_request",
	}

	code := c.FormValue("pre-authorized_code")
	pin := c.FormValue("tx_code")

	authorizationDetails := c.FormValue("authorization_details")

	logrus.Info("Code " + code + " Pin: " + pin + " authorization Details:" + authorizationDetails)
	storedAuth, err := a.authHandler.GetAuth(c.Context(), code)
	if err != nil {
		logrus.Error(fiber.NewError(fiber.StatusUnauthorized, "invalid auth code specified"))
		return c.Status(fiber.StatusBadRequest).JSON(InvalidErrorResponse)
	}

	if storedAuth.Pin != pin {
		logrus.Error(fiber.NewError(fiber.StatusUnauthorized, "authentication code and pin are not matching"))
		return c.Status(fiber.StatusBadRequest).JSON(InvalidErrorResponse)
	}

	if storedAuth.ExpiresAt.Before(time.Now()) {
		logrus.Error(fiber.NewError(fiber.StatusUnauthorized, "authentication expired"))
		return c.Status(fiber.StatusBadRequest).JSON(InvalidErrorResponse)
	}

	if _, err := a.authHandler.Delete(c.Context(), code); err != nil {
		logrus.Errorf("error occured while deleting authentication code from database: %v", err)
		logrus.Error(fiber.NewError(fiber.StatusInternalServerError, "could not delete authentication code from database"))
		return c.Status(fiber.StatusBadRequest).JSON(InvalidErrorResponse)
	}

	exp := storedAuth.ExpiresAt.Sub(time.Now()).Milliseconds() / 1000

	tokenResp := oauth.Token{
		TokenType:       "Bearer",
		ExpiresIn:       exp,
		CNonce:          storedAuth.Nonce,
		CNonceExpiresIn: exp,
	}

	var configuration *credential.CredentialConfigurationIdentifier
	if authorizationDetails != "" {
		decoded, err := url.QueryUnescape(authorizationDetails)
		if err != nil {
			logrus.Error(err)
			return c.Status(fiber.StatusBadRequest).JSON(InvalidErrorResponse)
		}

		// JSON unmarshalen
		var details oauth.AuthorizationDetails
		if err := json.Unmarshal([]byte(decoded), &details); err != nil {
			logrus.Error(err)
			return c.Status(fiber.StatusBadRequest).JSON(InvalidErrorResponse)
		}
		found := false
		index := 0
		for i, c := range storedAuth.CredentialConfigurations {
			if c.Id == details.CredentialConfigurationID {
				found = true
				index = i
				break
			}
		}

		if !found {
			logrus.Error("credential definition matches not to the request")
			return c.Status(fiber.StatusBadRequest).JSON(InvalidErrorResponse)
		}

		found = IsSubset(storedAuth.CredentialConfigurations[index].CredentialIdentifier, details.CredentialIdentifiers)

		if !found {
			logrus.Error("credential definition matches not to the request")
			return c.Status(fiber.StatusBadRequest).JSON(InvalidErrorResponse)
		}

		tokenResp.AuthorizationDetails = &oauth.AuthorizationDetails{
			Type:                      "openid_credential",
			CredentialConfigurationID: details.CredentialConfigurationID,
			CredentialIdentifiers:     details.CredentialIdentifiers,
		}

		configuration = &storedAuth.CredentialConfigurations[index]

	} else {
		if len(storedAuth.CredentialConfigurations) == 1 {
			tokenResp.AuthorizationDetails = &oauth.AuthorizationDetails{
				Type:                      "openid_credential",
				CredentialConfigurationID: storedAuth.CredentialConfigurations[0].Id,
				CredentialIdentifiers:     storedAuth.CredentialConfigurations[0].CredentialIdentifier,
			}
			configuration = &storedAuth.CredentialConfigurations[0]
		}

	}

	newToken, err := token.New(context.Background(), exp, storedAuth, configuration)
	if err != nil || newToken == "" {
		logrus.Errorf("error occured while retrieving token from authentication server: %v", err)
		logrus.Error(fiber.NewError(fiber.StatusInternalServerError, "could not retrieve token from authentication server"))
		return c.Status(fiber.StatusBadRequest).JSON(InvalidErrorResponse)

	}

	ttl := time.Duration(config.CurrentPreAuthBridgeConfig.DefaultTtlInMin) * time.Minute

	storedAuth.Token = newToken
	storedAuth.ExpiresAt = time.Now().Add(ttl)

	if err := a.authHandler.StoreAuth(c.Context(), newToken, *storedAuth); err != nil {
		logrus.Errorf("failed to store updated auth to db: %v", err)
		logrus.Error(fiber.NewError(fiber.StatusInternalServerError, "failed to process request"))
		return c.Status(fiber.StatusBadRequest).JSON(InvalidErrorResponse)
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
