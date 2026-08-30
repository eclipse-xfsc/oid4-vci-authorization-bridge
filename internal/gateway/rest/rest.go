package rest

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
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
	invalidRequest := fiber.Map{
		"error": "invalid_request",
	}

	invalidGrant := fiber.Map{
		"error": "invalid_grant",
	}

	//
	// Resolve tenant / signer configuration.
	//

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

	//
	// Validate grant type.
	//

	grantType := c.FormValue("grant_type")

	if grantType != string(oauth.PreAuthorizedCodeGrant) {
		logrus.Errorf(
			"unsupported grant type: %s",
			grantType,
		)

		return c.Status(fiber.StatusBadRequest).JSON(
			fiber.Map{
				"error": "unsupported_grant_type",
			},
		)
	}

	code := c.FormValue("pre-authorized_code")
	txCode := c.FormValue("tx_code")
	authorizationDetailsRaw := c.FormValue("authorization_details")

	if code == "" {
		logrus.Error("pre-authorized_code is missing")
		return c.Status(fiber.StatusBadRequest).JSON(invalidRequest)
	}

	logrus.WithFields(logrus.Fields{
		"grant_type":            grantType,
		"authorization_details": authorizationDetailsRaw != "",
	}).Debug("token request received")

	//
	// Resolve pre-authorized code.
	//

	storedAuth, err := a.authHandler.GetAuth(
		c.UserContext(),
		code,
	)
	if err != nil {
		logrus.WithError(err).Error(
			"invalid pre-authorized code",
		)

		return c.Status(fiber.StatusBadRequest).JSON(invalidGrant)
	}

	if storedAuth.ExpiresAt.Before(time.Now()) {
		logrus.Error("pre-authorized code expired")

		return c.Status(fiber.StatusBadRequest).JSON(invalidGrant)
	}

	//
	// Validate tx_code.
	//
	// An empty stored PIN means that this authorization does not require
	// a tx_code.
	//

	if storedAuth.Pin != "" {
		if txCode == "" {
			logrus.Error(
				"tx_code is required but missing",
			)

			return c.Status(fiber.StatusBadRequest).JSON(invalidGrant)
		}

		if storedAuth.Pin != txCode {
			logrus.Error(
				"tx_code does not match",
			)

			return c.Status(fiber.StatusBadRequest).JSON(invalidGrant)
		}
	}

	//
	// Resolve requested Credential Configuration.
	//

	var selectedConfiguration *credential.CredentialConfigurationIdentifier

	var tokenAuthorizationDetails []oauth.AuthorizationDetails

	if authorizationDetailsRaw != "" {
		var requestedDetails []oauth.AuthorizationDetails

		if err := json.Unmarshal(
			[]byte(authorizationDetailsRaw),
			&requestedDetails,
		); err != nil {
			logrus.WithError(err).Error(
				"invalid authorization_details",
			)

			return c.Status(fiber.StatusBadRequest).JSON(invalidRequest)
		}

		if len(requestedDetails) == 0 {
			logrus.Error(
				"authorization_details must not be empty",
			)

			return c.Status(fiber.StatusBadRequest).JSON(invalidRequest)
		}

		for _, details := range requestedDetails {
			if details.Type != oauth.AuthorizationDetailsTypeOpenIDCredential {
				logrus.Errorf(
					"unsupported authorization_details type: %s",
					details.Type,
				)

				return c.Status(fiber.StatusBadRequest).JSON(invalidRequest)
			}

			if details.CredentialConfigurationID == "" {
				logrus.Error(
					"credential_configuration_id is missing",
				)

				return c.Status(fiber.StatusBadRequest).JSON(invalidRequest)
			}

			found := false

			for i := range storedAuth.CredentialConfigurations {
				cfg := &storedAuth.CredentialConfigurations[i]

				if cfg.Id != details.CredentialConfigurationID {
					continue
				}

				found = true

				//
				// credential_identifiers in the request, when supplied,
				// must be part of the authorization represented by the
				// pre-authorized code.
				//

				if len(details.CredentialIdentifiers) > 0 &&
					!IsSubset(
						cfg.CredentialIdentifiers,
						details.CredentialIdentifiers,
					) {

					logrus.Error(
						"requested credential identifiers are not authorized",
					)

					return c.Status(fiber.StatusBadRequest).JSON(
						invalidRequest,
					)
				}

				credentialIdentifiers := cfg.CredentialIdentifiers

				if len(details.CredentialIdentifiers) > 0 {
					credentialIdentifiers = details.CredentialIdentifiers
				}

				tokenAuthorizationDetails = append(
					tokenAuthorizationDetails,
					oauth.AuthorizationDetails{
						Type: oauth.AuthorizationDetailsTypeOpenIDCredential,

						CredentialConfigurationID: cfg.Id,

						CredentialIdentifiers: credentialIdentifiers,

						Claims: details.Claims,
					},
				)

				//
				// Signer currently accepts only a single configuration.
				//
				// Until the signer API supports multiple credential
				// configurations, reject requests selecting multiple
				// configurations.
				//

				if selectedConfiguration != nil &&
					selectedConfiguration.Id != cfg.Id {

					logrus.Error(
						"multiple credential configurations are not supported by the signer",
					)

					return c.Status(fiber.StatusBadRequest).JSON(
						invalidRequest,
					)
				}

				selectedConfiguration = cfg

				break
			}

			if !found {
				logrus.Errorf(
					"credential configuration %q is not authorized",
					details.CredentialConfigurationID,
				)

				return c.Status(fiber.StatusBadRequest).JSON(
					invalidRequest,
				)
			}
		}

	} else if len(storedAuth.CredentialConfigurations) == 1 {
		cfg := &storedAuth.CredentialConfigurations[0]

		selectedConfiguration = cfg

		tokenAuthorizationDetails = []oauth.AuthorizationDetails{
			{
				Type: oauth.AuthorizationDetailsTypeOpenIDCredential,

				CredentialConfigurationID: cfg.Id,

				CredentialIdentifiers: cfg.CredentialIdentifiers,

				Claims: storedAuth.Claims,
			},
		}
	}

	//
	// Issue Access Token.
	//

	ttl := time.Duration(
		config.CurrentPreAuthBridgeConfig.DefaultTtlInMin,
	) * time.Minute

	tokenExpiresAt := time.Now().Add(ttl)

	newToken, err := a.signer.Sign(
		c.UserContext(),
		tokenExpiresAt.Unix(),
		storedAuth,
		selectedConfiguration,
		namespace,
		group,
		key,
		issuerKid,
		credentialEndpoint,
	)

	if err != nil {
		logrus.WithError(err).Error(
			"failed to create access token",
		)

		return c.Status(fiber.StatusInternalServerError).JSON(
			fiber.Map{
				"error": "server_error",
			},
		)
	}

	if newToken == "" {
		logrus.Error("signer returned empty access token")

		return c.Status(fiber.StatusInternalServerError).JSON(
			fiber.Map{
				"error": "server_error",
			},
		)
	}

	//
	// Store Access Token authorization.
	//

	storedAuth.Token = newToken
	storedAuth.ExpiresAt = tokenExpiresAt

	if err := a.authHandler.StoreAuth(
		c.UserContext(),
		newToken,
		*storedAuth,
	); err != nil {

		logrus.WithError(err).Error(
			"failed to store access token authorization",
		)

		return c.Status(fiber.StatusInternalServerError).JSON(
			fiber.Map{
				"error": "server_error",
			},
		)
	}

	//
	// Consume pre-authorized code only after token issuance succeeded.
	//

	if _, err := a.authHandler.Delete(
		c.UserContext(),
		code,
	); err != nil {

		logrus.WithError(err).Error(
			"failed to delete consumed pre-authorized code",
		)

		return c.Status(fiber.StatusInternalServerError).JSON(
			fiber.Map{
				"error": "server_error",
			},
		)
	}

	//
	// OID4VCI 1.0 Token Response.
	//
	// c_nonce and c_nonce_expires_in are intentionally not returned.
	// A nonce is obtained from the optional Nonce Endpoint instead.
	//

	tokenResponse := oauth.Token{
		AccessToken: newToken,
		TokenType:   "Bearer",
		ExpiresIn:   int64(ttl.Seconds()),

		AuthorizationDetails: tokenAuthorizationDetails,
	}

	return c.JSON(tokenResponse)
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
