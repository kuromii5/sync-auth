package config

import (
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/github"
)

type ClientInfoManager interface {
	GetClientID() string
	GetClientSecret() string
	Client() string
	Endpoint() oauth2.Endpoint
}

type GithubAuth struct {
	ClientID     string `yaml:"github_client_id" env:"GITHUB_CLIENT_ID" env-required:"true"`
	ClientSecret string `yaml:"github_client_secret" env:"GITHUB_CLIENT_SECRET" env-required:"true"`
}

func (g *GithubAuth) Client() string {
	return "github"
}

func (g *GithubAuth) GetClientID() string {
	return g.ClientID
}

func (g *GithubAuth) GetClientSecret() string {
	return g.ClientSecret
}

func (g *GithubAuth) Endpoint() oauth2.Endpoint {
	return github.Endpoint
}
