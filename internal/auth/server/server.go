package server

import (
	"fmt"
	"log"
	"log/slog"
	"net"

	"github.com/kuromii5/sync-auth/internal/service"
	"github.com/kuromii5/sync-auth/internal/transport"
	"google.golang.org/grpc"
)

type Server struct {
	logger *slog.Logger
	port   int
	api    *grpc.Server
}

func NewServer(logger *slog.Logger, port int, authService *service.Auth) *Server {
	api := transport.NewGrpcServer(authService)

	return &Server{
		logger: logger,
		port:   port,
		api:    api,
	}
}

func (s *Server) Run() {
	listener, err := net.Listen("tcp", fmt.Sprintf(":%d", s.port))
	if err != nil {
		log.Fatalf("failed to listen on port %d: %v", s.port, err)
	}

	s.logger.Info("Starting Authentication service...", slog.Int("port", s.port), slog.String("addr", listener.Addr().String()))

	if err := s.api.Serve(listener); err != nil {
		log.Fatalf("failed to serve gRPC server: %v", err)
	}
}

func (s *Server) Shutdown() {
	s.logger.Info("Stopping Authentication service...")

	s.api.GracefulStop()
}
