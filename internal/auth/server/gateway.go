package server

import (
	"context"
	"fmt"
	"log"
	"log/slog"
	"net/http"

	"github.com/gorilla/handlers"
	"github.com/gorilla/mux"
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
	r := mux.NewRouter()

	// Настраиваем CORS
	corsMiddleware := handlers.CORS(
		handlers.AllowedOrigins([]string{"http://localhost:3000"}),
		handlers.AllowedMethods([]string{"GET", "POST", "PUT", "DELETE", "OPTIONS"}),
		handlers.AllowedHeaders([]string{"Content-Type", "Authorization"}),
	)

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

	registerRoutes(r, g.grpcEndpoint, opts)

	// Attach the gRPC Gateway mux as a fallback handler
	r.PathPrefix("/").Handler(mux)

	handlerWithCORS := corsMiddleware(r)

	// Start HTTP server
	addr := fmt.Sprintf(":%d", g.port)
	g.logger.Info("Starting gRPC gateway...", slog.Int("port", g.port), slog.String("addr", addr))
	if err := http.ListenAndServe(addr, handlerWithCORS); err != nil {
		log.Fatalf("Failed to start gRPC gateway: %v", err)
	}
}

func registerRoutes(r *mux.Router, grpcEndpoint string, opts []grpc.DialOption) {
	r.HandleFunc("/oauth/callback", func(w http.ResponseWriter, r *http.Request) {
		code := r.URL.Query().Get("code")
		if code == "" {
			http.Error(w, "Code not found", http.StatusBadRequest)
			return
		}

		provider := "github" // r.URL.Query().Get("provider")
		if provider == "" {
			http.Error(w, "Provider not found", http.StatusBadRequest)
			return
		}

		// Create a new gRPC client connection
		conn, err := grpc.NewClient(grpcEndpoint, opts...)
		if err != nil {
			http.Error(w, "Failed to connect to gRPC server: "+err.Error(), http.StatusInternalServerError)
			return
		}
		defer conn.Close()

		client := auth.NewAuthClient(conn)
		_, err = client.ExchangeCodeForToken(context.Background(), &auth.ExchangeCodeRequest{
			Provider: provider,
			Code:     code,
		})
		if err != nil {
			http.Error(w, "Failed to exchange code: "+err.Error(), http.StatusInternalServerError)
			return
		}

	}).Methods("GET")
}
