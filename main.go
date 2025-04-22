package main

import (
	"context"
	"log"

	ce "github.com/eclipse-xfsc/cloud-event-provider"
	ctxPkg "github.com/eclipse-xfsc/microservice-core-go/pkg/ctx"
	logPkg "github.com/eclipse-xfsc/microservice-core-go/pkg/logr"
	"github.com/kelseyhightower/envconfig"
	"golang.org/x/sync/errgroup"

	"github.com/eclipse-xfsc/oid4-vci-authorization-bridge/internal/config"
	"github.com/eclipse-xfsc/oid4-vci-authorization-bridge/internal/database"
	"github.com/eclipse-xfsc/oid4-vci-authorization-bridge/internal/gateway/messaging"
	"github.com/eclipse-xfsc/oid4-vci-authorization-bridge/internal/gateway/rest"
	"github.com/eclipse-xfsc/oid4-vci-authorization-bridge/internal/security"
)

func main() {
	ctx := context.Background()

	if err := config.LoadConfig(); err != nil {
		log.Fatalf("failed to load config: %v", err)
	}

	if err := envconfig.Process("PREAUTHBRIDGE", &config.CurrentPreAuthBridgeConfig); err != nil {
		log.Fatalf("failed to load envconfig: %v", err)
	}

	conf := config.CurrentPreAuthBridgeConfig

	ceConfig := ce.Config{
		Protocol: ce.ProtocolTypeNats,
		Settings: conf.Nats,
	}

	logger, err := logPkg.New(conf.LogLevel, conf.IsDev, nil)
	if err != nil {
		log.Fatalf("failed to init logger: %v", err)
	}

	ctx = ctxPkg.WithLogger(ctx, *logger)

	redisDB, err := database.NewRedisDB(ctx, config.CurrentPreAuthBridgeConfig.Redis)
	if err != nil {
		log.Fatal(err)
	}

	authHandler := security.NewAuthHandler(redisDB)
	restApi := rest.NewRestApi(*authHandler)

	var errGrp errgroup.Group

	errGrp.Go(func() error {
		return restApi.Start(conf.ListenAddr, conf.ListenPort)
	})

	eventGW := messaging.NewEventGateway(ceConfig, *authHandler)

	errGrp.Go(func() error {
		return eventGW.Listen(ctx)
	})

	if err := errGrp.Wait(); err != nil {
		log.Fatal(err)
	}
}
