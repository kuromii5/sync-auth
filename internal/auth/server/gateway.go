package server

import (
	"context"
	"fmt"
	"log"
	"log/slog"
	"net/http"

	"github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
	auth "github.com/kuromii5/sync-auth/api/sync-auth/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/protobuf/encoding/protojson"
)

type Gateway struct {
	port         int
	logger       *slog.Logger
	grpcEndpoint string
}

func NewGateway(port int, grpcPort int, logger *slog.Logger) *Gateway {
	grpcEndpoint := fmt.Sprintf("localhost:%d", grpcPort)

	return &Gateway{
		port:         port,
		logger:       logger,
		grpcEndpoint: grpcEndpoint,
	}
}

func (g *Gateway) Run(ctx context.Context) {
	mux := runtime.NewServeMux(
		runtime.WithMarshalerOption(runtime.MIMEWildcard, &runtime.JSONPb{
			MarshalOptions: protojson.MarshalOptions{
				UseProtoNames: true,
			},
			UnmarshalOptions: protojson.UnmarshalOptions{
				DiscardUnknown: true,
			},
		}),
	)

	opts := []grpc.DialOption{
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	}

	// Register gRPC server endpoint
	err := auth.RegisterAuthHandlerFromEndpoint(ctx, mux, g.grpcEndpoint, opts)
	if err != nil {
		log.Fatalf("Failed to register gRPC gateway: %v", err)
	}

	// Start HTTP server
	addr := fmt.Sprintf(":%d", g.port)
	g.logger.Info("Starting gRPC gateway...", slog.Int("port", g.port), slog.String("addr", addr))
	if err := http.ListenAndServe(addr, mux); err != nil {
		log.Fatalf("Failed to start gRPC gateway: %v", err)
	}
}
