package redis

import (
	"context"
	"errors"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/redis/go-redis/v9"
)

var ErrTokenNotFound = errors.New("refresh token for user not found")

type TokenStorage struct {
	client *redis.Client
}

func NewTokenStorage(addr string) *TokenStorage {
	rdb := redis.NewClient(&redis.Options{
		Addr:     addr,
		Password: "",
		DB:       0,
	})

	if err := rdb.Ping(context.Background()).Err(); err != nil {
		log.Fatalf("Could not connect to Redis: %v", err)
	}

	return &TokenStorage{client: rdb}
}

func (t *TokenStorage) Set(ctx context.Context, userID int32, fingerprint, token string, expires time.Duration) error {
	const f = "redis.Set"

	key := fmt.Sprintf("%s:%s", token, fingerprint)
	if err := t.client.Set(ctx, key, userID, expires).Err(); err != nil {
		return fmt.Errorf("%s:%w", f, err)
	}

	// Add the token to the user's set of tokens
	userTokensKey := fmt.Sprintf("%d:tokens", userID)
	if err := t.client.SAdd(ctx, userTokensKey, key).Err(); err != nil {
		return fmt.Errorf("%s: failed to add token to user set: %w", f, err)
	}

	// Optionally, set the expiration for the user tokens set to match the token expiration
	if err := t.client.Expire(ctx, userTokensKey, expires).Err(); err != nil {
		return fmt.Errorf("%s: failed to set expiration for user tokens set: %w", f, err)
	}

	return nil
}

func (t *TokenStorage) UserID(ctx context.Context, token, fingerprint string) (string, error) {
	const f = "redis.UserID"

	key := fmt.Sprintf("%s:%s", token, fingerprint)
	userIdStr, err := t.client.Get(ctx, key).Result()
	if err != nil {
		if err == redis.Nil {
			return "", fmt.Errorf("%s:%w", f, ErrTokenNotFound)
		}

		return "", fmt.Errorf("%s:%w", f, err)
	}

	return userIdStr, nil
}

func (t *TokenStorage) Delete(ctx context.Context, userID int32, fingerprint string) error {
	const f = "redis.Delete"

	// Get all tokens for the user
	userTokensKey := fmt.Sprintf("%d:tokens", userID)
	tokens, err := t.client.SMembers(ctx, userTokensKey).Result()
	if err != nil {
		return fmt.Errorf("%s: failed to get tokens for user: %w", f, err)
	}

	// Find and delete the token that matches the fingerprint
	for _, token := range tokens {
		if strings.HasSuffix(token, fmt.Sprintf(":%s", fingerprint)) {
			// Delete the token
			if err := t.client.Del(ctx, token).Err(); err != nil {
				return fmt.Errorf("%s: failed to delete token: %w", f, err)
			}

			// Remove the token from the user's set
			if err := t.client.SRem(ctx, userTokensKey, token).Err(); err != nil {
				return fmt.Errorf("%s: failed to remove token from user set: %w", f, err)
			}
		}
	}

	return nil
}
