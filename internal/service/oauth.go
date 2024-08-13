package service

import (
	"encoding/json"
	"fmt"
	"net/http"
)

// This function fetches the user info from the OAuth provider
func fetchOAuthEmail(client *http.Client, provider string) (string, error) {
	switch provider {
	case "github":
		resp, err := client.Get("https://api.github.com/user/emails")
		if err != nil {
			return "", err
		}
		defer resp.Body.Close()

		var user struct {
			Email string `json:"email"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&user); err != nil {
			return "", err
		}

		return user.Email, nil
	default:
		return "", fmt.Errorf("unsupported provider: %s", provider)
	}
}
