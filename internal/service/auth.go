package service

import (
	"context"
	"errors"
	"fmt"
	"log/slog"

	"github.com/kuromii5/sync-auth/internal/models"
	"github.com/kuromii5/sync-auth/internal/repo/postgres"
	"github.com/kuromii5/sync-auth/internal/service/external"
	"github.com/kuromii5/sync-auth/internal/service/tokens"
	"github.com/kuromii5/sync-auth/pkg/hasher"
	le "github.com/kuromii5/sync-auth/pkg/logger/l_err"
	"golang.org/x/oauth2"
)

var (
	ErrInvalidCreds       = errors.New("invalid credentials")
	ErrUserExists         = errors.New("user already exists")
	ErrUserNotFound       = errors.New("user not found")
	ErrInvalidOAuthClient = errors.New("oauth client not found")
)

type Auth struct {
	log          *slog.Logger
	userSaver    UserSaver
	userProvider UserProvider
	oAuthClients map[string]*oauth2.Config
	tokenManager *tokens.TokenManager
}

type UserSaver interface {
	SaveUser(ctx context.Context, email string, hash []byte) (int32, error)
}
type UserProvider interface {
	User(ctx context.Context, email string) (models.User, error)
}

func NewAuthService(
	log *slog.Logger,
	userSaver UserSaver,
	userProvider UserProvider,
	tokenManager *tokens.TokenManager,
	oAuthClients map[string]*oauth2.Config,
) *Auth {
	return &Auth{
		log:          log,
		userSaver:    userSaver,
		userProvider: userProvider,
		tokenManager: tokenManager,
		oAuthClients: oAuthClients,
	}
}

func (a *Auth) SignUp(ctx context.Context, email, password string) (int32, error) {
	const f = "auth.Register"

	log := a.log.With(slog.String("func", f))
	log.Info("registering new user")

	hash, err := hasher.HashPassword(password)
	if err != nil {
		log.Error("failed to generate password", le.Err(err))

		return 0, fmt.Errorf("%s:%w", f, err)
	}

	id, err := a.userSaver.SaveUser(ctx, email, hash)
	if err != nil {
		if errors.Is(err, postgres.ErrUserExists) {
			a.log.Warn("user already exists", le.Err(err))

			return 0, fmt.Errorf("%s:%w", f, ErrUserExists)
		}

		log.Error("failed to save user", le.Err(err))
		return 0, fmt.Errorf("%s:%v", f, err)
	}

	log.Info("successfully registered new user")

	return id, nil
}

func (a *Auth) Login(ctx context.Context, email, password, fingerprint string) (models.TokenPair, error) {
	const f = "auth.Login"

	log := a.log.With(slog.String("func", f))
	log.Info("trying to log in user")

	user, err := a.userProvider.User(ctx, email)
	if err != nil {
		if errors.Is(err, postgres.ErrUserNotFound) {
			a.log.Warn("user not found", le.Err(err))

			return models.TokenPair{}, fmt.Errorf("%s:%w", f, ErrInvalidCreds)
		}

		a.log.Error("failed to get user", le.Err(err))
		return models.TokenPair{}, fmt.Errorf("%s:%w", f, err)
	}

	if err := hasher.CheckPassword(password, user.PasswordHash); err != nil {
		a.log.Warn("invalid credentials", le.Err(err))

		return models.TokenPair{}, fmt.Errorf("%s:%w", f, ErrInvalidCreds)
	}

	accessToken, err := a.tokenManager.NewAccessToken(ctx, user.ID)
	if err != nil {
		a.log.Error("failed to generate jwt access token", le.Err(err))

		return models.TokenPair{}, fmt.Errorf("%s:%w", f, err)
	}

	refreshToken, err := a.tokenManager.NewRefreshToken(ctx, user.ID, fingerprint)
	if err != nil {
		a.log.Error("failed to generate refresh token", le.Err(err))

		return models.TokenPair{}, fmt.Errorf("%s:%w", f, err)
	}

	log.Info("user logged in successfully")

	return models.TokenPair{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
	}, nil
}

func (a *Auth) ExchangeCodeForToken(ctx context.Context, code, provider string) (models.TokenPair, error) {
	const f = "auth.ExchangeCodeForToken"

	log := a.log.With(slog.String("func", f))
	log.Info("exchanging code for tokens")

	oauthConfig, exists := a.oAuthClients[provider]
	if !exists {
		log.Error("OAuth client not found", slog.String("provider", provider))

		return models.TokenPair{}, fmt.Errorf("%s:%w", f, ErrInvalidOAuthClient)
	}

	tokens, err := oauthConfig.Exchange(ctx, code)
	if err != nil {
		log.Error("failed to exchange code for token", le.Err(err))

		return models.TokenPair{}, fmt.Errorf("%s:%s", f, err)
	}

	email, err := external.GetGithubEmail(ctx, tokens.AccessToken)
	if err != nil {
		log.Error("failed to get email from token", le.Err(err))

		return models.TokenPair{}, fmt.Errorf("%s:%w", f, err)
	}

	user, err := a.userProvider.User(ctx, email)
	if err != nil {
		if errors.Is(err, postgres.ErrUserNotFound) {
			// Then save new user
			userID, err := a.userSaver.SaveUser(ctx, email, nil)
			if err != nil {
				log.Error("failed to save new user", le.Err(err))

				return models.TokenPair{}, fmt.Errorf("%s:%w", f, err)
			}

			user.ID = userID
		}

		log.Error("failed to get user", le.Err(err))

		return models.TokenPair{}, fmt.Errorf("%s:%w", f, err)
	}

	accessToken, err := a.tokenManager.NewAccessToken(ctx, user.ID)
	if err != nil {
		log.Error("failed to generate access token", le.Err(err))
		return models.TokenPair{}, fmt.Errorf("%s:%w", f, err)
	}

	refreshToken, err := a.tokenManager.NewRefreshToken(ctx, user.ID, "")
	if err != nil {
		log.Error("failed to generate refresh token", le.Err(err))
		return models.TokenPair{}, fmt.Errorf("%s:%w", f, err)
	}

	log.Info("user logged in successfully")

	return models.TokenPair{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
	}, nil
}

func (a *Auth) GetAccessToken(ctx context.Context, refreshToken, fingerprint string) (string, error) {
	const f = "service.GetAccessToken"

	log := a.log.With(slog.String("func", f))
	log.Info("attempting to generate new access token using refresh token")

	userID, err := a.tokenManager.ValidateRefreshToken(ctx, refreshToken, fingerprint)
	if err != nil {
		log.Error("failed to validate refresh token", le.Err(err))

		return "", fmt.Errorf("%s:%w", f, err)
	}

	accessToken, err := a.tokenManager.NewAccessToken(ctx, userID)
	if err != nil {
		log.Error("failed to create access token", le.Err(err))

		return "", fmt.Errorf("%s:%w", f, err)
	}

	log.Info("successfully generated new access token", slog.Int("user_id", int(userID)))

	return accessToken, nil
}

func (a *Auth) ValidateAccessToken(ctx context.Context, token string) (int32, error) {
	const f = "service.ValidateAccessToken"

	log := a.log.With(slog.String("func", f))
	log.Info("validating access token")

	userID, err := a.tokenManager.ValidateAccessToken(ctx, token)
	if err != nil {
		log.Warn("failed to validate access token", le.Err(err))

		return 0, fmt.Errorf("%s:%w", f, err)
	}

	log.Info("access token validated successfully", slog.Int("user_id", int(userID)))

	return userID, nil
}

func (a *Auth) Logout(ctx context.Context, accessToken, fingerprint string) error {
	const f = "service.Logout"

	log := a.log.With(slog.String("func", f))
	log.Info("logging out user")

	userID, err := a.tokenManager.ValidateAccessToken(ctx, accessToken)
	if err != nil {
		log.Warn("failed to validate access token", le.Err(err))

		return fmt.Errorf("%s:%w", f, err)
	}

	if err = a.tokenManager.Delete(ctx, userID, fingerprint); err != nil {
		log.Error("internal error", le.Err(err))

		return fmt.Errorf("%s:%w", f, err)
	}

	log.Info("successfully logged out user", slog.Int("user_id", int(userID)))

	return nil
}
