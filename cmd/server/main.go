package main

import "github.com/kuromii5/sync-auth/internal/auth"

func main() {
	authService := auth.NewAuthService()
	authService.Run()
}
