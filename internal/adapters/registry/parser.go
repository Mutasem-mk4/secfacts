package registry

import (
	"sync"

	sferr "github.com/axon/axon/internal/domain/errors"
	"github.com/axon/axon/internal/ports"
)

const opRegisterParser = "registry.ParserRegistry.Register"

type ParserRegistry struct {
	mu      sync.RWMutex
	parsers []ports.Parser
}

func NewParserRegistry(parsers ...ports.Parser) (*ParserRegistry, error) {
	registry := &ParserRegistry{}
	for _, parser := range parsers {
		if err := registry.Register(parser); err != nil {
			return nil, err
		}
	}

	return registry, nil
}

func (r *ParserRegistry) Register(parser ports.Parser) error {
	if parser == nil {
		return sferr.New(sferr.CodeInvalidArgument, opRegisterParser, "parser is required")
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	r.parsers = append(r.parsers, parser)
	return nil
}

func (r *ParserRegistry) MustRegister(parser ports.Parser) {
	if err := r.Register(parser); err != nil {
		panic(err)
	}
}

func (r *ParserRegistry) All() []ports.Parser {
	r.mu.RLock()
	defer r.mu.RUnlock()

	return append([]ports.Parser(nil), r.parsers...)
}

// Example:
//   reg := &ParserRegistry{}
//   reg.MustRegister(iemjson.Parser{})
//   reg.MustRegister(customsarif.Parser{})
