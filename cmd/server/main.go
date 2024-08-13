package main

import "github.com/kuromii5/sync-auth/internal/auth"

func main() {
	// Init app
	authService := auth.NewAuthService()

	// Run app
	authService.Run()
}
