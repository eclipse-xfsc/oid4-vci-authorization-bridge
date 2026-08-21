package main

import (
	"context"
	"log"

	ce "github.com/eclipse-xfsc/cloud-event-provider"
	ctxPkg "github.com/eclipse-xfsc/microservice-core-go/pkg/ctx"
	logPkg "github.com/eclipse-xfsc/microservice-core-go/pkg/logr"
	"github.com/eclipse-xfsc/oid4-vci-authorization-bridge/v2/internal/config"
	"github.com/eclipse-xfsc/oid4-vci-authorization-bridge/v2/internal/database"
	"github.com/eclipse-xfsc/oid4-vci-authorization-bridge/v2/internal/gateway/messaging"
	"github.com/eclipse-xfsc/oid4-vci-authorization-bridge/v2/internal/gateway/rest"
	"github.com/eclipse-xfsc/oid4-vci-authorization-bridge/v2/internal/health"
	"github.com/eclipse-xfsc/oid4-vci-authorization-bridge/v2/internal/security"
	"github.com/eclipse-xfsc/oid4-vci-authorization-bridge/v2/internal/token"
	"github.com/kelseyhightower/envconfig"
	"golang.org/x/sync/errgroup"
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

	ceConfig := ce.Config{Protocol: ce.ProtocolTypeNats, Settings: conf.Nats}
	logger, err := logPkg.New(conf.LogLevel, conf.IsDev, nil)
	if err != nil {
		log.Fatalf("failed to init logger: %v", err)
	}
	ctx = ctxPkg.WithLogger(ctx, *logger)

	redisDB, err := database.NewRedisDB(ctx, conf.Redis)
	if err != nil {
		log.Fatal(err)
	}
	authHandler := security.NewAuthHandler(redisDB)
	healthState := health.New(authHandler)

	eventGW, err := messaging.NewEventGateway(ceConfig, *authHandler, healthState)
	if err != nil {
		log.Fatalf("failed to initialize messaging responders: %v", err)
	}
	defer eventGW.Close()

	signer, err := token.NewSigner(ceConfig, healthState)
	if err != nil {
		log.Fatalf("failed to initialize signer client: %v", err)
	}
	defer signer.Close()

	restAPI := rest.NewRestApi(*authHandler, signer, healthState)
	errGrp, groupCtx := errgroup.WithContext(ctx)
	errGrp.Go(func() error { return eventGW.Listen(groupCtx) })
	errGrp.Go(func() error { return restAPI.Start(conf.ListenAddr, conf.ListenPort) })

	if err := errGrp.Wait(); err != nil {
		log.Fatal(err)
	}
}
