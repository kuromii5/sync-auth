package auth

import (
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/kuromii5/sync-auth/internal/auth/server"
	"github.com/kuromii5/sync-auth/internal/auth/server/logger"
	"github.com/kuromii5/sync-auth/internal/config"
	"github.com/kuromii5/sync-auth/internal/repo/postgres"
	"github.com/kuromii5/sync-auth/internal/repo/redis"
	"github.com/kuromii5/sync-auth/internal/service"
	"github.com/kuromii5/sync-auth/internal/service/tokens"
)

type AuthService struct {
	server *server.Server
}

func NewAuthService() *AuthService {
	// Init config
	config := config.Load()

	// Init oAuth clients
	clients := LoadClientsFromConfig(
		config.OauthGithub,
	)
	oAuthClients := LoadOauthClients(clients)

	// Init logger
	logger := logger.New(config.Env, config.LogLevel)

	// Init database
	db := postgres.NewDB(config.PGConfig)

	// Init token manager and token storage
	tokenStorage := redis.NewTokenStorage(config.TokensConfig.RedisAddr)
	tokenManager := tokens.NewTokenManager(logger, config.TokensConfig.Secret, config.TokensConfig.AccessTTL, config.TokensConfig.RefreshTTL, tokenStorage, tokenStorage, tokenStorage)

	// Init service
	authService := service.NewAuthService(logger, db, db, tokenManager, oAuthClients)

	// Init server
	server := server.NewServer(
		logger,
		config.GrpcPort,
		authService,
	)

	logger.Debug("",
		slog.Group("Settings",
			slog.Any("Postgres", config.PGConfig),
			slog.String("Environment", config.Env),
			slog.Int("GRPC port", config.GrpcPort),
		),
	)

	return &AuthService{server: server}
}

func (a *AuthService) Run() {
	go func() {
		a.server.Run()
	}()

	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)
	<-c

	a.Shutdown()
}

func (a *AuthService) Shutdown() {
	a.server.Shutdown()
}
