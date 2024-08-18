package service

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"math/rand"
	"time"

	"github.com/kuromii5/sync-auth/internal/models"
	"github.com/kuromii5/sync-auth/internal/repo/postgres"
	"github.com/kuromii5/sync-auth/internal/repo/redis"
	"github.com/kuromii5/sync-auth/internal/service/verification"
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
	log                 *slog.Logger
	VerificationManager *verification.VerificationManager
	userSaver           UserSaver
	userProvider        UserProvider
	accessTokenManager  AccessTokenManager
	refreshTokenManager RefreshTokenManager
	codeManager         CodeManager
	oAuthManager        OAuthManager
}

type UserSaver interface {
	SaveUser(ctx context.Context, email string, hash []byte) (int32, error)
}
type UserProvider interface {
	User(ctx context.Context, email string) (models.User, error)
	UserByID(ctx context.Context, userID int32) (models.User, error)
}

type AccessTokenManager interface {
	NewAccessToken(ctx context.Context, userID int32) (string, error)
	ValidateAccessToken(ctx context.Context, token string) (int32, error)
}
type RefreshTokenManager interface {
	NewRefreshToken(ctx context.Context, userID int32, fingerprint string) (string, error)
	ValidateRefreshToken(ctx context.Context, token string, fingerprint string) (int32, error)
	Delete(ctx context.Context, userID int32, fingerprint string) error
}

type OAuthManager interface {
	ConfigByProvider(provider string) *oauth2.Config
	GetGithubEmail(ctx context.Context, accessToken string) (string, error)
}

type CodeManager interface {
	SetCode(ctx context.Context, code, userID int32, expires time.Duration) error
	Code(ctx context.Context, userID int32) (int32, error)
	DeleteCode(ctx context.Context, userID int32) error
}

func NewAuthService(
	log *slog.Logger,
	VerificationManager *verification.VerificationManager,
	userSaver UserSaver,
	userProvider UserProvider,
	accessTokenManager AccessTokenManager,
	refreshTokenManager RefreshTokenManager,
	codeManager CodeManager,
	oAuthManager OAuthManager,
) *Auth {
	return &Auth{
		log:                 log,
		userSaver:           userSaver,
		userProvider:        userProvider,
		accessTokenManager:  accessTokenManager,
		refreshTokenManager: refreshTokenManager,
		VerificationManager: VerificationManager,
		codeManager:         codeManager,
		oAuthManager:        oAuthManager,
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

	accessToken, err := a.accessTokenManager.NewAccessToken(ctx, user.ID)
	if err != nil {
		a.log.Error("failed to generate jwt access token", le.Err(err))

		return models.TokenPair{}, fmt.Errorf("%s:%w", f, err)
	}

	refreshToken, err := a.refreshTokenManager.NewRefreshToken(ctx, user.ID, fingerprint)
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

func (a *Auth) Logout(ctx context.Context, accessToken, fingerprint string) error {
	const f = "service.Logout"

	log := a.log.With(slog.String("func", f))
	log.Info("logging out user")

	userID, err := a.accessTokenManager.ValidateAccessToken(ctx, accessToken)
	if err != nil {
		log.Warn("failed to validate access token", le.Err(err))

		return fmt.Errorf("%s:%w", f, err)
	}

	if err = a.refreshTokenManager.Delete(ctx, userID, fingerprint); err != nil {
		log.Error("internal error", le.Err(err))

		return fmt.Errorf("%s:%w", f, err)
	}

	log.Info("successfully logged out user", slog.Int("user_id", int(userID)))

	return nil
}

func (a *Auth) VerifyEmail(ctx context.Context, accessToken string) (models.VerifyEmailResp, error) {
	const f = "auth.VerifyEmail"

	log := a.log.With(slog.String("func", f))
	log.Info("verifying user email")

	userID, err := a.accessTokenManager.ValidateAccessToken(ctx, accessToken)
	if err != nil {
		log.Warn("failed to validate access token", le.Err(err))

		return models.VerifyEmailResp{}, fmt.Errorf("%s:%w", f, err)
	}

	user, err := a.userProvider.UserByID(ctx, userID)
	if err != nil {
		log.Warn("failed to get user email by id", le.Err(err))

		return models.VerifyEmailResp{}, fmt.Errorf("%s:%w", f, err)
	}
	email := user.Email

	// 6 digit code
	code := rand.Int31n(899_999) + 100_000
	err = a.codeManager.SetCode(ctx, code, userID, a.VerificationManager.CodeTTL)
	if err != nil {
		log.Error("failed to save verification code", le.Err(err))

		return models.VerifyEmailResp{}, fmt.Errorf("%s:%w", f, err)
	}

	err = a.VerificationManager.SendCode(email, code)
	if err != nil {
		log.Error("failed to send verification code on email", le.Err(err))

		return models.VerifyEmailResp{}, fmt.Errorf("%s:%w", f, err)
	}

	log.Info("code was successfully sent")

	return models.VerifyEmailResp{
		Status:  "code sent",
		CodeTTL: a.VerificationManager.CodeTTL,
	}, nil
}

func (a *Auth) ConfirmCode(ctx context.Context, code int32, accessToken string) (models.ConfirmCodeResp, error) {
	const f = "auth.ConfirmCode"

	log := a.log.With(slog.String("func", f))
	log.Info("confirming verification code")

	userID, err := a.accessTokenManager.ValidateAccessToken(ctx, accessToken)
	if err != nil {
		log.Warn("failed to validate access token", le.Err(err))

		return models.ConfirmCodeResp{}, fmt.Errorf("%s:%w", f, err)
	}

	realCode, err := a.codeManager.Code(ctx, userID)
	if err != nil {
		if errors.Is(err, redis.ErrCodeNotFound) {
			log.Error("code expired", le.Err(err))

			return models.ConfirmCodeResp{
				Success: false,
				Message: "Code expired",
			}, nil
		}
		log.Error("failed to get code from storage", le.Err(err))

		return models.ConfirmCodeResp{}, fmt.Errorf("%s:%w", f, err)
	}

	if realCode != code {
		log.Warn("user entered incorrect code", le.Err(err))

		return models.ConfirmCodeResp{
			Success: false,
			Message: "Incorrect code",
		}, nil
	}

	if err := a.codeManager.DeleteCode(ctx, userID); err != nil {
		log.Error("failed to delete code from storage", le.Err(err))

		return models.ConfirmCodeResp{}, fmt.Errorf("%s:%w", f, err)
	}

	log.Info("email was confirmed successfully")

	return models.ConfirmCodeResp{
		Success: true,
		Message: "Code confirmed",
	}, nil
}

func (a *Auth) ExchangeCodeForToken(ctx context.Context, code, provider, fingerprint string) (models.TokenPair, error) {
	const f = "auth.ExchangeCodeForToken"

	log := a.log.With(slog.String("func", f))
	log.Info("exchanging code for tokens")

	oauthConfig := a.oAuthManager.ConfigByProvider(provider)
	if oauthConfig == nil {
		log.Error("OAuth client not found", slog.String("provider", provider))

		return models.TokenPair{}, fmt.Errorf("%s:%w", f, ErrInvalidOAuthClient)
	}

	tokens, err := oauthConfig.Exchange(ctx, code)
	if err != nil {
		log.Error("failed to exchange code for token", le.Err(err))

		return models.TokenPair{}, fmt.Errorf("%s:%s", f, err)
	}

	email, err := a.oAuthManager.GetGithubEmail(ctx, tokens.AccessToken)
	if err != nil {
		log.Error("failed to get email from token", le.Err(err))

		return models.TokenPair{}, fmt.Errorf("%s:%w", f, err)
	}

	user, err := a.userProvider.User(ctx, email)
	switch {
	case err == nil:
	case errors.Is(err, postgres.ErrUserNotFound):
		userID, saveErr := a.userSaver.SaveUser(ctx, email, nil)
		if saveErr != nil {
			log.Error("failed to save new user", le.Err(saveErr))

			return models.TokenPair{}, fmt.Errorf("%s:%w", f, saveErr)
		}
		user.ID = userID
	default:
		log.Error("failed to get user", le.Err(err))

		return models.TokenPair{}, fmt.Errorf("%s:%w", f, err)
	}

	accessToken, err := a.accessTokenManager.NewAccessToken(ctx, user.ID)
	if err != nil {
		log.Error("failed to generate access token", le.Err(err))

		return models.TokenPair{}, fmt.Errorf("%s:%w", f, err)
	}

	refreshToken, err := a.refreshTokenManager.NewRefreshToken(ctx, user.ID, fingerprint)
	if err != nil {
		log.Error("failed to generate refresh token", le.Err(err))

		return models.TokenPair{}, fmt.Errorf("%s:%w", f, err)
	}

	log.Info("user logged in via external service successfully")

	return models.TokenPair{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
	}, nil
}

func (a *Auth) GetAccessToken(ctx context.Context, refreshToken, fingerprint string) (string, error) {
	const f = "service.GetAccessToken"

	log := a.log.With(slog.String("func", f))
	log.Info("attempting to generate new access token using refresh token")

	userID, err := a.refreshTokenManager.ValidateRefreshToken(ctx, refreshToken, fingerprint)
	if err != nil {
		log.Error("failed to validate refresh token", le.Err(err))

		return "", fmt.Errorf("%s:%w", f, err)
	}

	accessToken, err := a.accessTokenManager.NewAccessToken(ctx, userID)
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

	userID, err := a.accessTokenManager.ValidateAccessToken(ctx, token)
	if err != nil {
		log.Warn("failed to validate access token", le.Err(err))

		return 0, fmt.Errorf("%s:%w", f, err)
	}

	log.Info("access token validated successfully", slog.Int("user_id", int(userID)))

	return userID, nil
}
