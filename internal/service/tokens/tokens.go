package tokens

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"log/slog"
	"strconv"
	"time"

	"github.com/golang-jwt/jwt"
	le "github.com/kuromii5/sync-auth/pkg/logger/l_err"
)

type TokenManager struct {
	log *slog.Logger

	accessTTL  time.Duration
	refreshTTL time.Duration
	secret     string

	refreshTokenSetter  RefreshTokenSetter
	refreshTokenDeleter RefreshTokenDeleter
	userGetter          UserGetter
}

type RefreshTokenSetter interface {
	Set(ctx context.Context, userID int32, fingerprint, token string, expires time.Duration) error
}
type RefreshTokenDeleter interface {
	Delete(ctx context.Context, userID int32, fingerprint string) error
}
type UserGetter interface {
	UserID(ctx context.Context, token, fingerprint string) (string, error)
}

func NewTokenManager(
	log *slog.Logger,
	secret string,
	accessTTL, refreshTTL time.Duration,
	refreshTokenSetter RefreshTokenSetter,
	refreshTokenDeleter RefreshTokenDeleter,
	userGetter UserGetter,
) *TokenManager {
	return &TokenManager{
		log:                 log,
		accessTTL:           accessTTL,
		refreshTTL:          refreshTTL,
		secret:              secret,
		refreshTokenSetter:  refreshTokenSetter,
		refreshTokenDeleter: refreshTokenDeleter,
		userGetter:          userGetter,
	}
}

func (t *TokenManager) NewAccessToken(_ context.Context, userID int32) (string, error) {
	const f = "tokens.NewAccessToken"

	jwtToken := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.StandardClaims{
		Subject:   fmt.Sprintf("%d", userID),
		IssuedAt:  time.Now().Unix(),
		ExpiresAt: time.Now().Add(t.accessTTL).Unix(),
	})

	token, err := jwtToken.SignedString([]byte(t.secret))
	if err != nil {
		t.log.Error("failed to sign access token", le.Err(err), slog.Int("user_id", int(userID)))

		return "", fmt.Errorf("%s:%w", f, err)
	}

	return token, nil
}

func (t *TokenManager) NewRefreshToken(ctx context.Context, userID int32, fingerprint string) (string, error) {
	const f = "tokens.NewRefreshToken"

	log := t.log.With(slog.String("func", f))
	log.Info("generating new refresh token", slog.Int("user_id", int(userID)))

	b := make([]byte, 32)
	_, err := rand.Read(b)
	if err != nil {
		log.Error("failed to generate random bytes for refresh token", le.Err(err))

		return "", fmt.Errorf("%s:%w", f, err)
	}

	// encode token
	refreshToken := base64.URLEncoding.EncodeToString(b)

	// save token
	err = t.refreshTokenSetter.Set(ctx, userID, fingerprint, refreshToken, t.refreshTTL)
	if err != nil {
		log.Error("failed to save refresh token", le.Err(err))

		return "", fmt.Errorf("%s:%w", f, err)
	}

	log.Info("successfully generated and saved refresh token", slog.String("refresh_token", refreshToken))

	return refreshToken, nil
}

func (t *TokenManager) ValidateRefreshToken(ctx context.Context, token, fingerprint string) (int32, error) {
	const f = "tokens.ValidateRefreshToken"

	log := t.log.With(slog.String("func", f))
	log.Info("validating given refresh token", slog.String("refresh_token", token))

	userIDStr, err := t.userGetter.UserID(ctx, token, fingerprint)
	if err != nil {
		log.Error("failed to retrieve user ID for refresh token", le.Err(err))

		return 0, fmt.Errorf("%s:%w", f, err)
	}

	// convert string to int32
	id, err := strconv.ParseInt(userIDStr, 10, 32)
	if err != nil {
		log.Error("failed to parse user ID from string", le.Err(err))

		return 0, fmt.Errorf("%s:%w", f, err)
	}

	log.Info("successfully validated refresh token", slog.Int("user_id", int(id)))

	return int32(id), nil
}

func (t *TokenManager) ValidateAccessToken(ctx context.Context, token string) (int32, error) {
	const f = "tokenManager.ValidateAccessToken"

	log := t.log.With(slog.String("func", f))
	log.Info("validating given access token", slog.String("access_token", token))

	keyFunc := func(token *jwt.Token) (interface{}, error) {
		_, ok := token.Method.(*jwt.SigningMethodHMAC)
		if !ok {
			err := fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
			log.Error("unexpected signing method", le.Err(err))

			return nil, fmt.Errorf("%s:%w", f, err)
		}
		return []byte(t.secret), nil
	}

	accessToken, err := jwt.ParseWithClaims(token, &jwt.StandardClaims{}, keyFunc)
	if err != nil {
		log.Warn("failed to parse access token", le.Err(err))

		return 0, fmt.Errorf("%s:%w", f, err)
	}

	claims, ok := accessToken.Claims.(*jwt.StandardClaims)
	if !ok || !accessToken.Valid {
		err := fmt.Errorf("invalid token claims")
		log.Warn("invalid token claims", le.Err(err))

		return 0, fmt.Errorf("%s:%w", f, err)
	}

	// convert string to int32
	userID, err := strconv.ParseInt(claims.Subject, 10, 32)
	if err != nil {
		log.Error("failed to parse user ID", le.Err(err))

		return 0, fmt.Errorf("%s:%w", f, err)
	}

	return int32(userID), nil
}

func (t *TokenManager) Delete(ctx context.Context, userID int32, fingerprint string) error {
	const f = "tokenManager.Delete"

	log := t.log.With(slog.String("func", f))
	log.Info("Deleting refresh tokens for user", slog.Int("user_id", int(userID)))

	return t.refreshTokenDeleter.Delete(ctx, userID, fingerprint)
}
