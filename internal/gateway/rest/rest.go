package rest

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/eclipse-xfsc/oid4-vci-authorization-bridge/internal/config"
	"github.com/eclipse-xfsc/oid4-vci-authorization-bridge/internal/security"
	"github.com/eclipse-xfsc/oid4-vci-authorization-bridge/internal/token"
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

	code := c.FormValue("pre-authorized_code")
	pin := c.FormValue("tx_code")
	logrus.Info("Code " + code + " Pin: " + pin)
	storedAuth, err := a.authHandler.GetAuth(c.Context(), code)
	if err != nil {
		logrus.Error(err)
		return fiber.NewError(fiber.StatusUnauthorized, "invalid auth code specified")
	}

	if storedAuth.Pin != pin {
		return fiber.NewError(fiber.StatusUnauthorized, "authentication code and pin are not matching")
	}

	if storedAuth.ExpiresAt.Before(time.Now()) {
		return fiber.NewError(fiber.StatusUnauthorized, "authentication expired")
	}

	exp := storedAuth.ExpiresAt.Sub(time.Now()).Milliseconds() / 1000

	newToken, err := token.New(context.Background(), exp, storedAuth)
	if err != nil || newToken == "" {
		log.Errorf("error occured while retrieving token from authentication server: %v", err)
		return fiber.NewError(fiber.StatusInternalServerError, "could not retrieve token from authentication server")
	}

	ttl := time.Duration(config.CurrentPreAuthBridgeConfig.DefaultTtlInMin) * time.Minute

	storedAuth.Token = newToken
	storedAuth.ExpiresAt = time.Now().Add(ttl)

	if err := a.authHandler.StoreAuth(c.Context(), newToken, *storedAuth); err != nil {
		log.Errorf("failed to store updated auth to db: %v", err)
		return fiber.NewError(fiber.StatusInternalServerError, "failed to process request")
	}

	if _, err := a.authHandler.Delete(c.Context(), code); err != nil {
		log.Errorf("error occured while deleting authentication code from database: %v", err)
		return fiber.NewError(fiber.StatusInternalServerError, "could not delete authentication code from database")
	}

	tokenResp := oauth.Token{
		AccessToken:     newToken,
		TokenType:       "Bearer",
		ExpiresIn:       exp,
		CNonce:          storedAuth.Nonce,
		CNonceExpiresIn: exp,
	}

	if storedAuth.CredentialConfigurationId != "" && storedAuth.CredentialIdentifier != nil {
		tokenResp.AuthorizationDetails = &oauth.AuthorizationDetails{
			Type:                      "openid_credential",
			CredentialConfigurationID: storedAuth.CredentialConfigurationId,
			CredentialIdentifiers:     storedAuth.CredentialIdentifier,
		}
	}

	return c.JSON(tokenResp)
}
