package bootstrap

import (
	"io"
	"os"
	"strings"
	"time"

	"github.com/rs/zerolog"
)

func NewLogger(cfg Config) zerolog.Logger {
	level, err := zerolog.ParseLevel(strings.ToLower(cfg.LogLevel))
	if err != nil {
		level = zerolog.InfoLevel
	}

	writer := selectWriter(cfg.LogFormat, os.Stderr)
	logger := zerolog.New(writer).Level(level).With().Timestamp().Logger()

	return logger
}

func selectWriter(format string, out io.Writer) io.Writer {
	if strings.EqualFold(strings.TrimSpace(format), "json") {
		return out
	}

	return zerolog.ConsoleWriter{
		Out:        out,
		TimeFormat: time.RFC3339,
	}
}
