package config

import (
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/github"
)

type ClientInfoManager interface {
	Client() string
	ClientID() string
	ClientSecret() string
	RedirectURL() string
	Endpoint() oauth2.Endpoint
}

type GithubAuth struct {
	clientID     string `yaml:"github_client_id" env:"GITHUB_CLIENT_ID"`
	clientSecret string `yaml:"github_client_secret" env:"GITHUB_CLIENT_SECRET"`
}

func (g *GithubAuth) Client() string {
	return "github"
}

func (g *GithubAuth) ClientID() string {
	return g.clientID
}

func (g *GithubAuth) ClientSecret() string {
	return g.clientSecret
}

func (g *GithubAuth) RedirectURL() string {
	return "http://localhost:8080/github/callback"
}

func (g *GithubAuth) Endpoint() oauth2.Endpoint {
	return github.Endpoint
}
