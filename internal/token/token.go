package token

import (
	"context"

	"github.com/eclipse-xfsc/oid4-vci-authorization-bridge/internal/config"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/clientcredentials"
)

func New(ctx context.Context) (*oauth2.Token, error) {
	oAuthConfig := config.CurrentPreAuthBridgeConfig.OAuth

	tokenConfig := clientcredentials.Config{
		ClientID:       oAuthConfig.ClientId,
		ClientSecret:   oAuthConfig.ClientSecret,
		TokenURL:       oAuthConfig.ServerUrl,
		Scopes:         nil,
		EndpointParams: nil,
		AuthStyle:      0,
	}

	token, err := tokenConfig.Token(ctx)
	if err != nil {
		return nil, err
	}

	return token, nil
}
