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
		ServerUrl    string `mapstructure:"serverUrl" envconfig:"SERVERURL"`
		ClientId     string `mapstructure:"clientId" envconfig:"CLIENTID"`
		ClientSecret string `mapstructure:"clientSecret" envconfig:"CLIENT_SECRET"`
	} `mapstructure:"oAuth" envconfig:"OAUTH"`
	WellKnown struct {
		Issuer              string   `mapstructure:"issuer" json:"issuer"`
		TokenEndpoint       string   `mapstructure:"token_endpoint" json:"token_endpoint"`
		GrantTypesSupported []string `mapstructure:"grant_types_supported" json:"grant_types_supported"`
	} `mapstructure:"wellKnown"`
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
