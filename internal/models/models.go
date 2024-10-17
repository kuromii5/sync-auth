package models

import "time"

type User struct {
	ID            int32
	Email         string
	PasswordHash  []byte
	CreatedAt     time.Time
	UpdatedAt     time.Time
	EmailVerified bool
}

type TokenPair struct {
	AccessToken  string
	RefreshToken string
}

type VerifyEmailResp struct {
	Status  string
	CodeTTL time.Duration
}

type ConfirmCodeResp struct {
	Success bool
	Message string
}
