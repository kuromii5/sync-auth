package config

import (
	"log"
	"time"

	"github.com/ilyakaznacheev/cleanenv"
	"github.com/joho/godotenv"
)

type Config struct {
	Env      string `yaml:"env" env:"ENV"`
	LogLevel string `yaml:"log_evel" env:"LOG_LEVEL"`
	GrpcPort int    `yaml:"grpc_port" env:"GRPC_PORT"`

	PGConfig     PostgresConfig `yaml:"postgres"`
	TokensConfig TokensConfig   `yaml:"tokens"`

	OauthGithub GithubAuth `yaml:"github_auth"`
}

type TokensConfig struct {
	AccessTTL  time.Duration `yaml:"access_ttl" env:"TOKENS_ACCESS_TTL"`
	RefreshTTL time.Duration `yaml:"refresh_ttl" env:"TOKENS_REFRESH_TTL"`
	RedisAddr  string        `yaml:"redis_addr" env:"REDIS_ADDR"`
	Secret     string        `yaml:"secret" env:"TOKENS_SECRET"`
}

type PostgresConfig struct {
	User     string `env:"POSTGRES_USER" env-required:"true"`
	Password string `env:"POSTGRES_PASSWORD" env-required:"true"`
	Host     string `env:"POSTGRES_HOST" env-required:"true"`
	Port     int    `env:"POSTGRES_PORT" env-required:"true"`
	DBName   string `env:"POSTGRES_DBNAME" env-required:"true"`
	SSLMode  string `env:"POSTGRES_SSLMODE" env-default:"disable"`
}

func init() {
	err := godotenv.Load()
	if err != nil {
		log.Fatal("Error loading .env file")
	}
}

func Load() Config {
	var config Config

	if err := cleanenv.ReadEnv(&config); err != nil {
		log.Fatal("couldn't bind settings to config")
	}

	return config
}
