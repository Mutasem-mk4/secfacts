package ingestion

import (
	"fmt"
	"sync"

	"github.com/axon/axon/internal/core/ports"
)

var (
	registry = make(map[string]ports.Parser)
	mu       sync.RWMutex
)

// Register adds a parser to the global registry.
func Register(parser ports.Parser) {
	mu.Lock()
	defer mu.Unlock()
	registry[parser.Name()] = parser
}

// GetParser retrieves a parser by its name.
func GetParser(name string) (ports.Parser, error) {
	mu.RLock()
	defer mu.RUnlock()
	p, ok := registry[name]
	if !ok {
		return nil, fmt.Errorf("parser not found: %s", name)
	}
	return p, nil
}

// AvailableParsers returns a list of registered parser names.
func AvailableParsers() []string {
	mu.RLock()
	defer mu.RUnlock()
	keys := make([]string, 0, len(registry))
	for k := range registry {
		keys = append(keys, k)
	}
	return keys
}
