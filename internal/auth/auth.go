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
	"github.com/kuromii5/sync-auth/internal/service/oauth"
	"github.com/kuromii5/sync-auth/internal/service/tokens"
	"github.com/kuromii5/sync-auth/internal/service/verification"
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

	// Init Redis storage
	storage := redis.NewTokenStorage(config.TokensConfig.RedisAddr)

	// Init managers
	tokenManager := tokens.NewTokenManager(logger, config.TokensConfig.Secret, config.TokensConfig.AccessTTL, config.TokensConfig.RefreshTTL, storage, storage, storage)
	verificationManager := verification.NewVerificationManager(logger, config.EVConfig.CodeTTL, config.EVConfig.AppEmail, config.EVConfig.AppPassword, config.EVConfig.AppSmtpHost)
	oAuthManager := oauth.NewOAuthManager(logger, oAuthClients)

	// Init service
	authService := service.NewAuthService(logger, verificationManager, db, db, tokenManager, tokenManager, storage, oAuthManager)

	// Init server
	server := server.NewServer(
		logger,
		config.Port,
		authService,
	)

	logger.Debug("",
		slog.Group("Settings",
			slog.Any("Postgres", config.PGConfig),
			slog.String("Environment", config.Env),
			slog.Int("Port", config.Port),
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
