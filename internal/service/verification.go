package service

import (
	"context"
	"errors"
	"fmt"
	"log/slog"

	"math/rand"

	"github.com/kuromii5/sync-auth/internal/models"
	"github.com/kuromii5/sync-auth/internal/repo/redis"
	le "github.com/kuromii5/sync-auth/pkg/logger/l_err"
)

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

	if err := a.userSaver.VerifyUser(ctx, userID); err != nil {
		log.Error("failed to verify user in db", le.Err(err))

		return models.ConfirmCodeResp{}, fmt.Errorf("%s:%w", f, err)
	}

	log.Info("email was confirmed successfully")

	return models.ConfirmCodeResp{
		Success: true,
		Message: "Code confirmed",
	}, nil
}
