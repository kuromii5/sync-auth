package auth

import (
	"github.com/kuromii5/sync-auth/internal/config"
	"golang.org/x/oauth2"
)

func LoadClientsFromConfig(githubConfig config.GithubAuth) []config.ClientInfoManager {
	var clients []config.ClientInfoManager

	// add more implemented clients here
	clients = append(clients, &githubConfig)

	return clients
}

func LoadOauthClients(clients []config.ClientInfoManager) map[string]*oauth2.Config {
	oauthClients := make(map[string]*oauth2.Config)

	for _, client := range clients {
		clientConfig := &oauth2.Config{
			ClientID:     client.GetClientID(),
			ClientSecret: client.GetClientSecret(),
			Endpoint:     client.Endpoint(),
			RedirectURL:  "http://localhost:8080/oauth/callback",
			Scopes:       []string{"user:email"},
		}

		oauthClients[client.Client()] = clientConfig
	}

	return oauthClients
}
