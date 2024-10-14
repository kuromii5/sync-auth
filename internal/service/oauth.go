package service

import (
	"context"
	"errors"
	"fmt"
	"log/slog"

	"github.com/kuromii5/sync-auth/internal/repo/postgres"
	le "github.com/kuromii5/sync-auth/pkg/logger/l_err"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
)

func (a *Auth) ExchangeCodeForToken(ctx context.Context, code, provider, fingerprint string) error {
	const f = "auth.ExchangeCodeForToken"

	log := a.log.With(slog.String("func", f))
	log.Info("exchanging code for tokens")

	oauthConfig := a.oAuthManager.ConfigByProvider(provider)
	if oauthConfig == nil {
		log.Error("OAuth client not found", slog.String("provider", provider))

		return fmt.Errorf("%s:%w", f, ErrInvalidOAuthClient)
	}

	tokens, err := oauthConfig.Exchange(ctx, code)
	if err != nil {
		log.Error("failed to exchange code for token", le.Err(err))

		return fmt.Errorf("%s:%s", f, err)
	}

	email, err := a.oAuthManager.GetGithubEmail(ctx, tokens.AccessToken)
	if err != nil {
		log.Error("failed to get email from token", le.Err(err))

		return fmt.Errorf("%s:%w", f, err)
	}

	user, err := a.userProvider.User(ctx, email)
	switch {
	case err == nil:
	case errors.Is(err, postgres.ErrUserNotFound):
		userID, saveErr := a.userSaver.SaveUser(ctx, email, nil)
		if saveErr != nil {
			log.Error("failed to save new user", le.Err(saveErr))

			return fmt.Errorf("%s:%w", f, saveErr)
		}
		user.ID = userID
	default:
		log.Error("failed to get user", le.Err(err))

		return fmt.Errorf("%s:%w", f, err)
	}

	accessToken, err := a.accessTokenManager.NewAccessToken(ctx, user.ID)
	if err != nil {
		log.Error("failed to generate access token", le.Err(err))

		return fmt.Errorf("%s:%w", f, err)
	}

	refreshToken, err := a.refreshTokenManager.NewRefreshToken(ctx, user.ID, fingerprint)
	if err != nil {
		log.Error("failed to generate refresh token", le.Err(err))

		return fmt.Errorf("%s:%w", f, err)
	}

	md := metadata.New(map[string]string{})
	md.Append("Set-Cookie", fmt.Sprintf("access_token=%s", accessToken))
	md.Append("Set-Cookie", fmt.Sprintf("refresh_token=%s", refreshToken))
	grpc.SetHeader(ctx, md)
	log.Debug("Generated metadata", slog.Any("md", md))

	log.Info("user logged in via external service successfully")

	return nil
}
