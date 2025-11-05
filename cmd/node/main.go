// Copyright 2025 AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"math"
	"net/http"
	"os"
	"os/signal"
	"time"

	identityapi "github.com/agntcy/identity/api/server"
	idpg "github.com/agntcy/identity/internal/core/id/postgres"
	issuerpg "github.com/agntcy/identity/internal/core/issuer/postgres"
	"github.com/agntcy/identity/internal/core/issuer/verification"
	vcpg "github.com/agntcy/identity/internal/core/vc/postgres"
	issuergrpc "github.com/agntcy/identity/internal/issuer/grpc"
	"github.com/agntcy/identity/internal/node"
	nodegrpc "github.com/agntcy/identity/internal/node/grpc"
	"github.com/agntcy/identity/internal/node/grpc/interceptors"
	"github.com/agntcy/identity/internal/pkg/cmd"
	"github.com/agntcy/identity/internal/pkg/db"
	"github.com/agntcy/identity/internal/pkg/grpcserver"
	"github.com/agntcy/identity/internal/pkg/grpcutil"
	"github.com/agntcy/identity/internal/pkg/log"
	"github.com/agntcy/identity/pkg/oidc"
	"github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
	"github.com/rs/cors"
	"go.opentelemetry.io/contrib/instrumentation/google.golang.org/grpc/otelgrpc"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/keepalive"
)

// ------------------------ GLOBAL -------------------- //

var maxMsgSize = math.MaxInt64

// ------------------------ GLOBAL -------------------- //

//nolint:funlen // Ignore linting for main function
func main() {
	ctx, cancel := context.WithCancel(context.Background())

	config, err := cmd.GetConfiguration[Configuration]()
	if err != nil {
		log.WithError(err).Fatal("failed to start")
	}

	if config == nil {
		log.Error("config is nil")
		os.Exit(1)
	}

	// Configure log level
	log.Init(config.IsDev())
	log.SetLogLevel(config.LogLevel)

	log.Info("Starting in env:", config.GoEnv)

	// Create a gRPC server object
	//nolint:lll // Ignore linting for long lines
	var kaep = keepalive.EnforcementPolicy{
		MinTime: time.Duration(
			config.ServerGrpcKeepAliveEnvorcementPolicyMinTime,
		) * time.Second, // If a client pings more than once every X seconds, terminate the connection
		PermitWithoutStream: config.ServerGrpcKeepAliveEnvorcementPolicyPermitWithoutStream, // Allow pings even when there are no active streams
	}

	var kaServerParams = keepalive.ServerParameters{
		MaxConnectionIdle: time.Duration(
			config.ServerGrpcKeepAliveServerParametersMaxConnectionIdle,
		) * time.Second, // If a client is idle for X seconds, send a GOAWAY
		Time: time.Duration(
			config.ServerGrpcKeepAliveServerParametersTime,
		) * time.Second, // Ping the client if it is idle for X seconds to ensure the connection is still active
		Timeout: time.Duration(
			config.ServerGrpcKeepAliveServerParametersTimeout,
		) * time.Second, // Wait X second for the ping ack before assuming the connection is dead
	}

	// Create a database context
	dbContext := db.NewContext(
		config.DbHost,
		config.DbPort,
		config.DbName,
		config.DbUsername,
		config.DbPassword,
		config.DbUseSsl,
	)

	// Connect to the database
	err = dbContext.Connect()
	if err != nil {
		log.Fatal(err)
	}

	// Migrate the database
	err = dbContext.AutoMigrate(
		&issuerpg.Issuer{},
		&idpg.ResolverMetadata{},
		&idpg.Service{},
		&idpg.VerificationMethod{},
		&vcpg.VerifiableCredential{},
		&vcpg.CredentialSchema{},
		&vcpg.CredentialStatus{},
	)
	if err != nil {
		log.Fatal(err)
	}

	// Disconnect the database client when done
	defer func() {
		if err = dbContext.Disconnect(); err != nil {
			log.Fatal(err)
		}
	}()

	// Unhandled errors interceptor
	errorInterceptor := interceptors.NewErrorInterceptor(config.IsProd())

	// Create a GRPC server
	grpcSrv, err := grpcserver.New(
		config.ServerGrpcHost,
		grpc.ChainUnaryInterceptor(
			interceptors.ContextualLoggerUnary,
			errorInterceptor.Unary,
		),
		grpc.StatsHandler(otelgrpc.NewServerHandler()),
		grpc.MaxRecvMsgSize(maxMsgSize),
		grpc.MaxSendMsgSize(maxMsgSize),
		grpc.KeepaliveEnforcementPolicy(kaep),
		grpc.KeepaliveParams(kaServerParams),
	)
	if err != nil {
		log.Error(err)
	}

	defer func() {
		_ = grpcSrv.Shutdown(ctx)
	}()

	// Create OIDC parser
	oidcParser := oidc.NewParser()

	// Create repositories
	issuerRepository := issuerpg.NewRepository(dbContext)
	idRepository := idpg.NewIdRepository(dbContext)
	vcRepository := vcpg.NewRepository(dbContext)

	// Create internal services
	verificationService := verification.NewService(oidcParser, issuerRepository)
	nodeIssuerService := node.NewIssuerService(issuerRepository, verificationService)
	idGenerator := node.NewIDGenerator(verificationService)
	nodeIdService := node.NewIdService(
		idRepository,
		idGenerator,
	)
	nodeVcService := node.NewVerifiableCredentialService(
		idRepository,
		verificationService,
		vcRepository,
	)

	register := identityapi.GrpcServiceRegister{
		IdServiceServer:     nodegrpc.NewIdService(nodeIdService),
		IssuerServiceServer: nodegrpc.NewIssuerService(nodeIssuerService),
		VcServiceServer:     nodegrpc.NewVcService(nodeVcService),
		LocalServiceServer:  issuergrpc.NewLocalService(),
	}

	register.RegisterGrpcHandlers(grpcSrv.Server)

	// Serve gRPC server
	log.Info("Serving gRPC on:", config.ServerGrpcHost)

	go func() {
		if err := grpcSrv.Run(ctx); err != nil {
			log.Fatal(err)
		}
	}()

	// Create a client connection to the gRPC server we just started
	// This is where the gRPC-Gateway proxies the requests

	//nolint:lll // Allow long line for struct
	var kaClientParams = keepalive.ClientParameters{
		Time: time.Duration(
			config.ClientGrpcKeepAliveClientParametersTime,
		) * time.Second, // Ping the client if it is idle for X seconds to ensure the connection is still active
		Timeout: time.Duration(
			config.ClientGrpcKeepAliveClientParametersTimeout,
		) * time.Second, // Wait X second for the ping ack before assuming the connection is dead
		PermitWithoutStream: config.ClientGrpcKeepAliveClientParametersPermitWithoutStream, // Allow pings even when there are no active streams
	}

	conn, err := grpc.NewClient(
		"0.0.0.0"+config.ServerGrpcHost,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithStatsHandler(otelgrpc.NewClientHandler()),
		grpc.WithKeepaliveParams(kaClientParams),
		grpc.WithDefaultCallOptions(
			grpc.MaxCallRecvMsgSize(maxMsgSize),
			grpc.MaxCallSendMsgSize(maxMsgSize),
		),
	)
	if err != nil {
		log.Error("Failed to dial server:", err)
	}

	gwOpts := []runtime.ServeMuxOption{
		runtime.WithHealthzEndpoint(grpc_health_v1.NewHealthClient(conn)),
		runtime.WithIncomingHeaderMatcher(grpcutil.CustomMatcher),
	}
	gwMux := runtime.NewServeMux(gwOpts...)

	err = register.RegisterHttpHandlers(ctx, gwMux, conn)
	if err != nil {
		log.Error(err)
	}

	// Setup cors for dev
	options := cors.Options{
		AllowedOrigins: []string{"*"},
		AllowedMethods: []string{"PUT", "GET", "DELETE", "POST", "PATCH"},
		AllowedHeaders: []string{
			"X-Requested-With",
			"content-type",
			"Origin",
			"Accept",
			"Authorization",
		},
		AllowCredentials: true,

		// Enable Debugging for testing, consider disabling in production
		Debug: true,
	}

	// Check current env
	if config.GoEnv != "development" {
		options.Debug = false
	}

	c := cors.New(options)

	gwServer := &http.Server{
		Addr:              config.ServerHttpHost,
		Handler:           c.Handler(gwMux),
		WriteTimeout:      time.Duration(config.HttpServerWriteTimeout) * time.Second,
		IdleTimeout:       time.Duration(config.HttpServerIdleTimeout) * time.Second,
		ReadTimeout:       time.Duration(config.HttpServerReadTimeout) * time.Second,
		ReadHeaderTimeout: time.Duration(config.HttpServerReadHeaderTimeout) * time.Second,
	}

	defer func() {
		_ = gwServer.Shutdown(ctx)
	}()

	go func() {
		log.Info("Serving gRPC-Gateway on:", config.ServerHttpHost)

		if err := gwServer.ListenAndServe(); err != nil {
			log.Fatal(err)
		}
	}()

	interruptChannel := make(chan os.Signal, 1)
	signal.Notify(interruptChannel, os.Interrupt)
	<-interruptChannel

	log.Info("Exiting the node")

	cancel()
}
