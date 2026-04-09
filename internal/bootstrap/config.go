package bootstrap

import (
	"os"
	"path/filepath"
	"strings"
)

const (
	defaultLogLevel  = "info"
	defaultLogFormat = "console"
	defaultWorkers   = 4
)

type Config struct {
	LogLevel    string
	LogFormat   string
	Workers     int
	ConfigPaths []string
	LogPath     string
}

func LoadConfig() Config {
	cfg := Config{
		LogLevel:    envOrDefault("AXON_LOG_LEVEL", defaultLogLevel),
		LogFormat:   envOrDefault("AXON_LOG_FORMAT", defaultLogFormat),
		Workers:     defaultWorkers,
		ConfigPaths: defaultConfigPaths(),
		LogPath:     envOrDefault("AXON_LOG_PATH", "/var/log/axon/axon.log"),
	}

	if value := strings.TrimSpace(os.Getenv("AXON_WORKERS")); value != "" {
		if workers, ok := parsePositiveInt(value); ok {
			cfg.Workers = workers
		}
	}

	return cfg
}

func defaultConfigPaths() []string {
	paths := []string{"/etc/axon/"}
	home, err := os.UserHomeDir()
	if err == nil && strings.TrimSpace(home) != "" {
		paths = append(paths, filepath.Join(home, ".config", "axon")+"/")
	}
	if override := strings.TrimSpace(os.Getenv("AXON_CONFIG_PATH")); override != "" {
		paths = []string{override}
	}
	return paths
}

func envOrDefault(key string, fallback string) string {
	value := strings.TrimSpace(os.Getenv(key))
	if value == "" {
		return fallback
	}

	return value
}
