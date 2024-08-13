package offlog

import (
	"context"
	"log/slog"
)

func New() *slog.Logger {
	return slog.New(NewOffHandler())
}

type OffHandler struct{}

func NewOffHandler() *OffHandler {
	return &OffHandler{}
}

func (h *OffHandler) Handle(_ context.Context, _ slog.Record) error {
	return nil
}

func (h *OffHandler) WithAttrs(_ []slog.Attr) slog.Handler {
	return h
}

func (h *OffHandler) WithGroup(_ string) slog.Handler {
	return h
}

func (h *OffHandler) Enabled(_ context.Context, _ slog.Level) bool {
	return false
}
