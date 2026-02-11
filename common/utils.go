package common

import (
	"log/slog"
	"os"
)

func NewMessage(mt MessageType, parts ...[]byte) []byte {
	msg := []byte{byte(mt)}

	for _, part := range parts {
		msg = append(msg, part...)
	}

	return msg
}

func NewLogger(level slog.Level) *slog.Logger {
	return slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		AddSource: true,
		Level:     level,
	}))
}
