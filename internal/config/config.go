package config

import (
	"errors"
	"strings"

	ce "github.com/eclipse-xfsc/cloud-event-provider"

	configPkg "github.com/eclipse-xfsc/microservice-core-go/pkg/config"
	redisPkg "github.com/eclipse-xfsc/microservice-core-go/pkg/db/redis"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/viper"
)

type preAuthBridgeConfiguration struct {
	configPkg.BaseConfig
	Nats            ce.NatsConfig   `mapstructure:"nats" envconfig:"NATS"`
	Redis           redisPkg.Config `mapstructure:"database" envconfig:"REDIS"`
	DefaultTtlInMin int             `mapstructure:"defaultTtlInMin"`
	OfferTopic      string          `mapstructure:"offerTopic"`
	TwoFactorTopic  string          `mapstructure:"twoFactorTopic"`
	OAuth           struct {
		SignerTopic        string `envconfig:"SIGNER_TOPIC"`
		SignerJwksUrl      string `envconfig:"SIGNER_JWKS_URL"`
		CredentialEndpoint string `envconfig:"CREDENTIALENDPOINT"`
		Key                string `envconfig:"KEY"`
		Namespace          string `envconfig:"NAMESPACE"`
		GroupId            string `envconfig:"GROUPID"`
		IssuerKid          string `envconfig:"ISSUER_KID"`
		Engine             string `envconfig:"ENGINE"`
	} `mapstructure:"oAuth" envconfig:"OAUTH"`
	//will be serialized to openid-configuration
	WellKnown struct {
		Issuer              string   `mapstructure:"issuer" json:"issuer"`
		TokenEndpoint       string   `mapstructure:"token_endpoint" json:"token_endpoint"`
		GrantTypesSupported []string `mapstructure:"grant_types_supported" json:"grant_types_supported"`
		Jwks                string   `envconfig:"JWKS" json:"jwks_uri"`
	} `mapstructure:"wellKnown"`
	WellKnownAuth struct {
		Issuer        string `mapstructure:"issuer" json:"issuer"`
		TokenEndpoint string `mapstructure:"token_endpoint" json:"token_endpoint"`
		Jwks          string `envconfig:"JWKS" json:"jwks_uri"`

		GrantTypesSupported []string `mapstructure:"grant_types_supported" envconfig:"GRANT_TYPES_SUPPORTED" json:"grant_types_supported"`

		ResponseTypesSupported []string `mapstructure:"response_types_supported" envconfig:"RESPONSE_TYPES_SUPPORTED" json:"response_types_supported,omitempty"`

		TokenEndpointAuthMethodsSupported []string `mapstructure:"token_endpoint_auth_methods_supported" envconfig:"TOKEN_ENDPOINT_AUTH_METHODS_SUPPORTED" json:"token_endpoint_auth_methods_supported"`

		CodeChallengeMethodsSupported []string `mapstructure:"code_challenge_methods_supported" envconfig:"CODE_CHALLENGE_METHODS_SUPPORTED" json:"code_challenge_methods_supported,omitempty"`

		AuthorizationDetailsTypesSupported []string `mapstructure:"authorization_details_types_supported" envconfig:"AUTHORIZATION_DETAILS_TYPES_SUPPORTED" json:"authorization_details_types_supported,omitempty"`

		PreAuthorizedGrantAnonymousAccessSupported bool `mapstructure:"pre-authorized_grant_anonymous_access_supported" envconfig:"PRE_AUTHORIZED_GRANT_ANONYMOUS_ACCESS_SUPPORTED" json:"pre-authorized_grant_anonymous_access_supported,omitempty"`
	} `mapstructure:"wellKnownAuth"`
}

var CurrentPreAuthBridgeConfig preAuthBridgeConfiguration

func LoadConfig() error {
	setDefaults()
	readConfig()

	if err := viper.Unmarshal(&CurrentPreAuthBridgeConfig); err != nil {
		return err
	}

	var configuredGrantTypesSupported = CurrentPreAuthBridgeConfig.WellKnown.GrantTypesSupported

	if len(configuredGrantTypesSupported) > 1 {
		return errors.New("unsupported config option: grant_types_supported should only have 1 value")
	}

	if configuredGrantTypesSupported[0] != "urn:ietf:params:oauth:grant-type:pre-authorized_code" {
		return errors.New("unsupported config option: grant_types_supported only supports \"urn:ietf:params:oauth:grant-type:pre-authorized_code\"")
	}

	return nil
}

func readConfig() {
	viper.SetConfigName("config")
	viper.SetConfigType("yaml")
	viper.AddConfigPath(".")

	viper.SetEnvPrefix("PREAUTHBRIDGE")
	viper.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
	viper.AutomaticEnv()
	if err := viper.ReadInConfig(); err != nil {
		var configFileNotFoundError viper.ConfigFileNotFoundError
		if errors.As(err, &configFileNotFoundError) {
			log.Printf("Configuration not found but environment variables will be taken into account.")
		}
	}
}

func setDefaults() {
	viper.SetDefault("isDev", false)
	viper.SetDefault("databaseUrl", "redis://root:pass@redis_db:6379/0")
	viper.SetDefault("defaultTtlInMin", 30)
	viper.SetDefault("offerTopic", "offer")
	viper.SetDefault("twoFactorTopic", "pin")

	// oAuth default values
	viper.SetDefault("oAuth.serverUrl", "http://hydra:4444/oauth2/token")
	viper.SetDefault("oAuth.clientId", "bridge")
	viper.SetDefault("oAuth.clientSecret", "secret")

	// .wellknown endpoint default
	viper.SetDefault("wellKnown.issuer", "http://localhost:8080")
	viper.SetDefault("wellKnown.token_endpoint", "http://localhost:8080/token")
	viper.SetDefault("wellKnown.grant_types_supported", []string{"urn:ietf:params:oauth:grant-type:pre-authorized_code"})
}
