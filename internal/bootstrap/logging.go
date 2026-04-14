package bootstrap

import (
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/rs/zerolog"
)

func NewLogger(cfg Config) zerolog.Logger {
	level, err := zerolog.ParseLevel(strings.ToLower(cfg.LogLevel))
	if err != nil {
		level = zerolog.InfoLevel
	}

	writer := selectWriter(cfg.LogFormat, combinedLogWriter(cfg.LogPath))
	logger := zerolog.New(writer).Level(level).With().Timestamp().Logger()

	return logger
}

func combinedLogWriter(logPath string) io.Writer {
	writers := []io.Writer{os.Stderr}
	fileWriter, err := openLogFile(logPath)
	if err == nil {
		writers = append(writers, fileWriter)
	}
	return io.MultiWriter(writers...)
}

func openLogFile(path string) (*os.File, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return nil, os.ErrInvalid
	}
	// Restrict log directory permissions (rwx------) to protect sensitive data
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	// Restrict log file permissions (rw-------) to protect sensitive data
	return os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
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
