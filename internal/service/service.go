package service

import (
	"context"
	"errors"
	"log/slog"
	"time"

	"github.com/kuromii5/sync-auth/internal/models"
	"github.com/kuromii5/sync-auth/internal/service/verification"
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
	VerifyUser(ctx context.Context, userID int32) error
}
type UserProvider interface {
	UserByEmail(ctx context.Context, email string) (models.User, error)
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
