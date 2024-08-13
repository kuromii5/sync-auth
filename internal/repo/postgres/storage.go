package postgres

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/kuromii5/sync-auth/internal/config"
	"github.com/kuromii5/sync-auth/internal/models"
)

var (
	ErrUserExists   = errors.New("user already exists")
	ErrUserNotFound = errors.New("user not found")
)

type DB struct {
	Pool *pgxpool.Pool
}

func PGConnectionStr(config config.PostgresConfig) string {
	return fmt.Sprintf(
		"postgres://%s:%s@%s:%d/%s?sslmode=%s",
		config.User,
		config.Password,
		config.Host,
		config.Port,
		config.DBName,
		config.SSLMode,
	)
}

func NewDB(config config.PostgresConfig) *DB {
	dbUrl := PGConnectionStr(config)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	poolConfig, err := pgxpool.ParseConfig(dbUrl)
	if err != nil {
		log.Fatal("unable to parse db url")
	}

	pool, err := pgxpool.NewWithConfig(ctx, poolConfig)
	if err != nil {
		log.Fatal("unable to connect to db")
	}

	return &DB{Pool: pool}
}

func (d *DB) SaveUser(ctx context.Context, email string, passwordHash []byte) (int32, error) {
	const f = "postgres.SaveUser"

	query := "INSERT INTO users (email, pass_hash) VALUES ($1, $2) RETURNING id"

	var userID int32
	err := d.Pool.QueryRow(ctx, query, email, passwordHash).Scan(&userID)
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" {
			return 0, fmt.Errorf("%s:%w", f, ErrUserExists)
		}

		return 0, fmt.Errorf("%s:%w", f, err)
	}

	return userID, nil
}

func (d *DB) User(ctx context.Context, email string) (models.User, error) {
	const f = "postgres.User"

	query := "SELECT id, email, pass_hash, created_at, updated_at FROM users WHERE email = $1"

	var user models.User
	err := d.Pool.QueryRow(ctx, query, email).
		Scan(&user.ID, &user.Email, &user.PasswordHash, &user.CreatedAt, &user.UpdatedAt)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return models.User{}, fmt.Errorf("%s:%w", f, ErrUserNotFound)
		}

		return models.User{}, fmt.Errorf("%s:%w", f, err)
	}

	return user, nil
}
