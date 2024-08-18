package redis

import (
	"context"
	"errors"
	"fmt"
	"log"
	"strconv"
	"strings"
	"time"

	"github.com/redis/go-redis/v9"
)

var (
	ErrTokenNotFound = errors.New("refresh token for user not found")
	ErrCodeNotFound  = errors.New("verification code not found")
)

type Storage struct {
	client *redis.Client
}

func NewTokenStorage(addr string) *Storage {
	rdb := redis.NewClient(&redis.Options{
		Addr:     addr,
		Password: "",
		DB:       0,
	})

	if err := rdb.Ping(context.Background()).Err(); err != nil {
		log.Fatalf("Could not connect to Redis: %v", err)
	}

	return &Storage{client: rdb}
}

func (s *Storage) SetRefreshToken(ctx context.Context, userID int32, fingerprint, token string, expires time.Duration) error {
	const f = "redis.SetRefreshToken"

	key := fmt.Sprintf("%s:%s", token, fingerprint)
	if err := s.client.Set(ctx, key, userID, expires).Err(); err != nil {
		return fmt.Errorf("%s:%w", f, err)
	}

	// Add the token to the user's set of tokens
	userTokensKey := fmt.Sprintf("%d:tokens", userID)
	if err := s.client.SAdd(ctx, userTokensKey, key).Err(); err != nil {
		return fmt.Errorf("%s: failed to add token to user set: %w", f, err)
	}

	// Optionally, set the expiration for the user tokens set to match the token expiration
	if err := s.client.Expire(ctx, userTokensKey, expires).Err(); err != nil {
		return fmt.Errorf("%s: failed to set expiration for user tokens set: %w", f, err)
	}

	return nil
}

func (s *Storage) UserID(ctx context.Context, token, fingerprint string) (string, error) {
	const f = "redis.UserID"

	key := fmt.Sprintf("%s:%s", token, fingerprint)
	userIdStr, err := s.client.Get(ctx, key).Result()
	if err != nil {
		if err == redis.Nil {
			return "", fmt.Errorf("%s:%w", f, ErrTokenNotFound)
		}

		return "", fmt.Errorf("%s:%w", f, err)
	}

	return userIdStr, nil
}

func (s *Storage) DeleteRefreshToken(ctx context.Context, userID int32, fingerprint string) error {
	const f = "redis.DeleteRefreshToken"

	// Get all tokens for the user
	userTokensKey := fmt.Sprintf("%d:tokens", userID)
	tokens, err := s.client.SMembers(ctx, userTokensKey).Result()
	if err != nil {
		return fmt.Errorf("%s: failed to get tokens for user: %w", f, err)
	}

	// Find and delete the token that matches the fingerprint
	for _, token := range tokens {
		if strings.HasSuffix(token, fmt.Sprintf(":%s", fingerprint)) {
			if err := s.client.Del(ctx, token).Err(); err != nil {
				return fmt.Errorf("%s: failed to delete token: %w", f, err)
			}

			// Remove the token from the user's set
			if err := s.client.SRem(ctx, userTokensKey, token).Err(); err != nil {
				return fmt.Errorf("%s: failed to remove token from user set: %w", f, err)
			}
		}
	}

	return nil
}

func (s *Storage) SetCode(ctx context.Context, code, userID int32, expires time.Duration) error {
	const f = "redis.SetCode"

	key := fmt.Sprintf("%d:code", userID)

	if err := s.client.Set(ctx, key, code, expires).Err(); err != nil {
		return fmt.Errorf("%s: failed to set code: %w", f, err)
	}

	return nil
}

func (s *Storage) Code(ctx context.Context, userID int32) (int32, error) {
	const f = "redis.Code"

	key := fmt.Sprintf("%d:code", userID)

	codeStr, err := s.client.Get(ctx, key).Result()
	if err != nil {
		if err == redis.Nil {
			return 0, fmt.Errorf("%s: code not found for user: %w", f, ErrCodeNotFound)
		}

		return 0, fmt.Errorf("%s: failed to get code: %w", f, err)
	}

	code, err := strconv.Atoi(codeStr)
	if err != nil {
		return 0, fmt.Errorf("%s: failed to convert code to int32: %w", f, err)
	}

	return int32(code), nil
}

func (s *Storage) DeleteCode(ctx context.Context, userID int32) error {
	const f = "redis.DeleteCode"

	key := fmt.Sprintf("%d:code", userID)

	if err := s.client.Del(ctx, key).Err(); err != nil {
		return fmt.Errorf("%s: failed to delete code: %w", f, err)
	}

	return nil
}
