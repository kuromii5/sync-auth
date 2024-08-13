package logger

import (
	"log/slog"
	"os"

	offlog "github.com/kuromii5/sync-auth/pkg/logger/off"
	prettylog "github.com/kuromii5/sync-auth/pkg/logger/pretty"
)

var (
	local = "local"
	dev   = "dev"
	prod  = "prod"
)

var (
	debug = "debug"
	info  = "info"
	warn  = "warn"
	err   = "error"
)

func getLogLevel(logLevel string) slog.Level {
	switch logLevel {
	case debug:
		return slog.LevelDebug
	case info:
		return slog.LevelInfo
	case warn:
		return slog.LevelWarn
	case err:
		return slog.LevelError
	default:
		return slog.LevelInfo // by default - info
	}
}

func New(env string, logLevel string) *slog.Logger {
	level := getLogLevel(logLevel)

	switch env {
	case local:
		return prettylog.NewTextLogger(os.Stdout, level)
	case dev:
		return slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: level}))
	case prod:
		return slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: level}))
	default:
		return offlog.New()
	}
}
