package common

import (
	"log/slog"
	"os"
)

func NewLogger(level slog.Level) *slog.Logger {
	return slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		AddSource: true,
		Level:     level,
	}))
}

func StartWorkers[T any](n int, channel chan T, do func(t T)) {
	for range n {
		go func() {
			for val := range channel {
				do(val)
			}
		}()
	}
}
