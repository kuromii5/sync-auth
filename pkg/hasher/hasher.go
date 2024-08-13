package hasher

import (
	"fmt"

	"golang.org/x/crypto/bcrypt"
)

// convert password to hash string
func HashPassword(password string) ([]byte, error) {
	hashPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return nil, fmt.Errorf("failed to hash password %w", err)
	}
	return hashPassword, nil
}

// check password is valid or not
func CheckPassword(password string, hashPassword []byte) error {
	return bcrypt.CompareHashAndPassword(hashPassword, []byte(password))
}
