package postgres

import (
	"context"
	"errors"
	"fmt"
	"log"
	"time"

	"github.com/jackc/pgconn"
	"github.com/jackc/pgx/v4"
	"github.com/jackc/pgx/v4/pgxpool"
	"github.com/kuromii5/sync-auth/internal/config"
	"github.com/kuromii5/sync-auth/internal/models"
)

var (
	ErrUserExists   = errors.New("user already exists")
	ErrUserNotFound = errors.New("user not found")
)

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

type PoolDB interface {
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
	Exec(ctx context.Context, sql string, arguments ...any) (pgconn.CommandTag, error)
}

type DB struct {
	Pool PoolDB
}

func NewDB(config config.PostgresConfig) *DB {
	dbUrl := PGConnectionStr(config)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	poolConfig, err := pgxpool.ParseConfig(dbUrl)
	if err != nil {
		log.Fatal("unable to parse db url")
	}

	pool, err := pgxpool.ConnectConfig(ctx, poolConfig)
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

func (d *DB) UserByEmail(ctx context.Context, email string) (models.User, error) {
	const f = "postgres.UserByEmail"

	query := "SELECT id, email, pass_hash, created_at, updated_at, email_verified FROM users WHERE email = $1"

	var user models.User
	err := d.Pool.QueryRow(ctx, query, email).
		Scan(&user.ID, &user.Email, &user.PasswordHash, &user.CreatedAt, &user.UpdatedAt, &user.EmailVerified)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return models.User{}, fmt.Errorf("%s:%w", f, ErrUserNotFound)
		}

		return models.User{}, fmt.Errorf("%s:%w", f, err)
	}

	return user, nil
}

func (d *DB) UserByID(ctx context.Context, userID int32) (models.User, error) {
	const f = "postgres.UserByID"

	query := "SELECT id, email, pass_hash, created_at, updated_at, email_verified FROM users WHERE id = $1"

	var user models.User
	err := d.Pool.QueryRow(ctx, query, userID).
		Scan(&user.ID, &user.Email, &user.PasswordHash, &user.CreatedAt, &user.UpdatedAt, &user.EmailVerified)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return models.User{}, fmt.Errorf("%s:%w", f, ErrUserNotFound)
		}

		return models.User{}, fmt.Errorf("%s:%w", f, err)
	}

	return user, nil
}

func (d *DB) VerifyUser(ctx context.Context, userID int32) error {
	const f = "postgres.VerifyUser"

	query := "UPDATE users SET email_verified = TRUE, updated_at = NOW() WHERE id = $1"

	res, err := d.Pool.Exec(ctx, query, userID)
	if err != nil {
		return fmt.Errorf("%s:%w", f, err)
	}

	rowsAffected := res.RowsAffected()
	if rowsAffected == 0 {
		return fmt.Errorf("%s:%w", f, ErrUserNotFound)
	}

	return nil
}
