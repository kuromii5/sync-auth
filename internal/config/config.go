package config

import (
	"log"
	"time"

	"github.com/ilyakaznacheev/cleanenv"
	"github.com/joho/godotenv"
)

type Config struct {
	Env      string `yaml:"env" env:"ENV" env-default:"local"`
	LogLevel string `yaml:"log_evel" env:"LOG_LEVEL" env-default:"info"`
	Port     int    `yaml:"port" env:"PORT" env-required:"true"`

	PGConfig     PostgresConfig          `yaml:"postgres"`
	TokensConfig TokensConfig            `yaml:"tokens"`
	EVConfig     EmailVerificationConfig `yaml:"email_verification"`

	OauthGithub GithubAuth `yaml:"github_auth"`
}

type TokensConfig struct {
	AccessTTL  time.Duration `yaml:"access_ttl" env:"TOKENS_ACCESS_TTL" env-default:"15m"`
	RefreshTTL time.Duration `yaml:"refresh_ttl" env:"TOKENS_REFRESH_TTL" env-default:"240h"`
	RedisAddr  string        `yaml:"redis_addr" env:"REDIS_ADDR" env-required:"true"`
	Secret     string        `yaml:"secret" env:"TOKENS_SECRET" env-required:"true"`
}

type PostgresConfig struct {
	User     string `yaml:"user" env:"POSTGRES_USER" env-required:"true"`
	Password string `yaml:"password" env:"POSTGRES_PASSWORD" env-required:"true"`
	Host     string `yaml:"host" env:"POSTGRES_HOST" env-required:"true"`
	Port     int    `yaml:"port" env:"POSTGRES_PORT" env-required:"true"`
	DBName   string `yaml:"dbname" env:"POSTGRES_DBNAME" env-required:"true"`
	SSLMode  string `yaml:"sslmode" env:"POSTGRES_SSLMODE" env-default:"disable"`
}

type EmailVerificationConfig struct {
	CodeTTL     time.Duration `yaml:"email_code_ttl" env:"EMAIL_CODE_TTL" env-default:"120s"`
	AppEmail    string        `yaml:"app_email" env:"APP_EMAIL" env-required:"true"`
	AppPassword string        `yaml:"app_password" env:"APP_PASSWORD" env-required:"true"`
	AppSmtpHost string        `yaml:"app_smtp_host" env:"APP_SMTP_HOST" env-required:"true"`
}

func Load() Config {
	var config Config

	err := godotenv.Load()
	if err != nil {
		log.Fatal("Error loading .env file")
	}

	if err := cleanenv.ReadEnv(&config); err != nil {
		log.Fatal("couldn't bind settings to config")
	}

	return config
}
