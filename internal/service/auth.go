package service

import (
	"context"
	"errors"
	"fmt"
	"log/slog"

	"github.com/kuromii5/sync-auth/internal/repo/postgres"
	"github.com/kuromii5/sync-auth/pkg/hasher"
	le "github.com/kuromii5/sync-auth/pkg/logger/l_err"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
)

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

func (a *Auth) Login(ctx context.Context, email, password, fingerprint string) error {
	const f = "auth.Login"

	log := a.log.With(slog.String("func", f))
	log.Info("trying to log in user")

	user, err := a.userProvider.UserByEmail(ctx, email)
	if err != nil {
		if errors.Is(err, postgres.ErrUserNotFound) {
			a.log.Warn("user not found", le.Err(err))

			return fmt.Errorf("%s:%w", f, ErrInvalidCreds)
		}
		a.log.Error("failed to get user", le.Err(err))

		return fmt.Errorf("%s:%w", f, err)
	}

	if err := hasher.CheckPassword(password, user.PasswordHash); err != nil {
		a.log.Warn("invalid credentials", le.Err(err))

		return fmt.Errorf("%s:%w", f, ErrInvalidCreds)
	}

	accessToken, err := a.accessTokenManager.NewAccessToken(ctx, user.ID)
	if err != nil {
		a.log.Error("failed to generate jwt access token", le.Err(err))

		return fmt.Errorf("%s:%w", f, err)
	}

	refreshToken, err := a.refreshTokenManager.NewRefreshToken(ctx, user.ID, fingerprint)
	if err != nil {
		a.log.Error("failed to generate refresh token", le.Err(err))

		return fmt.Errorf("%s:%w", f, err)
	}

	md := metadata.New(map[string]string{})
	md.Append("Set-Cookie", fmt.Sprintf("access_token=%s", accessToken))
	md.Append("Set-Cookie", fmt.Sprintf("refresh_token=%s", refreshToken))
	grpc.SendHeader(ctx, md)
	log.Debug("Generated metadata", slog.Any("md", md))

	log.Info("user logged in successfully")

	return nil
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
