package service

import (
	"context"
	"fmt"
	"log/slog"

	le "github.com/kuromii5/sync-auth/pkg/logger/l_err"
)

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
