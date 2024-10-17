package postgres

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"testing"
	"time"

	"github.com/jackc/pgconn"
	"github.com/jackc/pgx/v4"
	"github.com/kuromii5/sync-auth/internal/models"
	"github.com/pashagolub/pgxmock"
	"github.com/stretchr/testify/suite"
)

// SUITE

type PostgresTestSuite struct {
	suite.Suite
	mockPool pgxmock.PgxPoolIface
	db       *DB
}

func (s *PostgresTestSuite) SetupTest() {
	s.mockPool, _ = pgxmock.NewPool()
	s.db = &DB{Pool: s.mockPool}
}
func (s *PostgresTestSuite) TearDownTest() {
	err := s.mockPool.ExpectationsWereMet()
	if err != nil {
		s.T().Errorf("there were unfulfilled expectations: %v", err)
	}

	s.mockPool.Close()
}

// ACTUAL TESTS

func (s *PostgresTestSuite) TestSaveUser_Success() {
	s.mockPool.ExpectQuery("INSERT INTO users").
		WithArgs("test@example.com", []byte("hashed_password")).
		WillReturnRows(pgxmock.NewRows([]string{"id"}).AddRow(int32(1)))

	got, err := s.db.SaveUser(context.Background(), "test@example.com", []byte("hashed_password"))
	s.NoError(err)
	s.Equal(int32(1), got)
}

func (s *PostgresTestSuite) TestSaveUser_UserExists() {
	s.mockPool.ExpectQuery("INSERT INTO users").
		WithArgs("test@example.com", []byte("hashed_password")).
		WillReturnError(&pgconn.PgError{Code: "23505"})

	_, err := s.db.SaveUser(context.Background(), "test@example.com", []byte("hashed_password"))
	s.Error(err)
	s.True(errors.Is(err, ErrUserExists), "ErrUserExists was expected")
}

func (s *PostgresTestSuite) TestUserByEmail_Success() {
	createdAt, _ := time.Parse("2006-01-02", "2023-10-12")
	updatedAt, _ := time.Parse("2006-01-02", "2023-10-12")
	s.mockPool.ExpectQuery(regexp.QuoteMeta("SELECT id, email, pass_hash, created_at, updated_at, email_verified FROM users WHERE email = $1")).
		WithArgs("test@example.com").
		WillReturnRows(pgxmock.NewRows([]string{"id", "email", "pass_hash", "created_at", "updated_at", "email_verified"}).
			AddRow(int32(1), "test@example.com", []byte("hashed_password"), createdAt, updatedAt, false))

	got, err := s.db.UserByEmail(context.Background(), "test@example.com")
	s.NoError(err)

	expectedUser := models.User{
		ID:            1,
		Email:         "test@example.com",
		PasswordHash:  []byte("hashed_password"),
		CreatedAt:     createdAt,
		UpdatedAt:     updatedAt,
		EmailVerified: false,
	}
	s.Equal(expectedUser, got)
}

func (s *PostgresTestSuite) TestUserByEmail_NotFound() {
	s.mockPool.ExpectQuery(regexp.QuoteMeta("SELECT id, email, pass_hash, created_at, updated_at, email_verified FROM users WHERE email = $1")).
		WithArgs("test1@example.com").
		WillReturnError(pgx.ErrNoRows)

	_, err := s.db.UserByEmail(context.Background(), "test1@example.com")
	s.Error(err)
	s.True(errors.Is(err, ErrUserNotFound), "ErrUserNotFound was expected")
}

func (s *PostgresTestSuite) TestUserByID_Success() {
	createdAt, _ := time.Parse("2006-01-02", "2023-10-12")
	updatedAt, _ := time.Parse("2006-01-02", "2023-10-12")
	s.mockPool.ExpectQuery(regexp.QuoteMeta("SELECT id, email, pass_hash, created_at, updated_at, email_verified FROM users WHERE id = $1")).
		WithArgs(int32(1)).
		WillReturnRows(pgxmock.NewRows([]string{"id", "email", "pass_hash", "created_at", "updated_at", "email_verified"}).
			AddRow(int32(1), "test@example.com", []byte("hashed_password"), createdAt, updatedAt, false))

	got, err := s.db.UserByID(context.Background(), int32(1))
	s.NoError(err)

	expectedUser := models.User{
		ID:            1,
		Email:         "test@example.com",
		PasswordHash:  []byte("hashed_password"),
		CreatedAt:     createdAt,
		UpdatedAt:     updatedAt,
		EmailVerified: false,
	}
	s.Equal(expectedUser, got)
}

func (s *PostgresTestSuite) TestUserByID_NotFound() {
	s.mockPool.ExpectQuery(regexp.QuoteMeta("SELECT id, email, pass_hash, created_at, updated_at, email_verified FROM users WHERE id = $1")).
		WithArgs(int32(1)).
		WillReturnError(pgx.ErrNoRows)

	_, err := s.db.UserByID(context.Background(), int32(1))
	s.Error(err)
	s.True(errors.Is(err, ErrUserNotFound), "ErrUserNotFound was expected")
}

func (s *PostgresTestSuite) TestVerifyUser_Success() {
	s.mockPool.ExpectExec(regexp.QuoteMeta("UPDATE users SET email_verified = TRUE, updated_at = NOW() WHERE id = $1")).
		WithArgs(int32(1)).
		WillReturnResult(pgxmock.NewResult("UPDATE", 1))

	err := s.db.VerifyUser(context.Background(), int32(1))
	s.NoError(err)
}

func (s *PostgresTestSuite) TestVerifyUser_NotFound() {
	s.mockPool.ExpectExec(regexp.QuoteMeta("UPDATE users SET email_verified = TRUE, updated_at = NOW() WHERE id = $1")).
		WithArgs(int32(999)).
		WillReturnResult(pgxmock.NewResult("UPDATE", 0))

	err := s.db.VerifyUser(context.Background(), int32(999))
	s.Error(err)
	s.True(errors.Is(err, ErrUserNotFound))
}

func (s *PostgresTestSuite) TestVerifyUser_Error() {
	s.mockPool.ExpectExec(regexp.QuoteMeta("UPDATE users SET email_verified = TRUE, updated_at = NOW() WHERE id = $1")).
		WithArgs(int32(1)).
		WillReturnError(fmt.Errorf("some error"))

	err := s.db.VerifyUser(context.Background(), int32(1))
	s.Error(err)
}

// RUN TESTS

func TestPostgresTestSuite(t *testing.T) {
	suite.Run(t, new(PostgresTestSuite))
}
