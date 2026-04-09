package registry

import (
	"strings"
	"sync"

	sferr "github.com/axon/axon/internal/domain/errors"
	"github.com/axon/axon/internal/ports"
)

const (
	opRegisterExporter = "registry.ExporterRegistry.Register"
	opExporterByFormat = "registry.ExporterRegistry.ByFormat"
)

type ExporterRegistry struct {
	mu        sync.RWMutex
	exporters map[string]ports.Exporter
}

func NewExporterRegistry(exporters ...ports.Exporter) (*ExporterRegistry, error) {
	registry := &ExporterRegistry{
		exporters: make(map[string]ports.Exporter, len(exporters)),
	}
	for _, exporter := range exporters {
		if err := registry.Register(exporter); err != nil {
			return nil, err
		}
	}

	return registry, nil
}

func (r *ExporterRegistry) Register(exporter ports.Exporter) error {
	if exporter == nil {
		return sferr.New(sferr.CodeInvalidArgument, opRegisterExporter, "exporter is required")
	}

	format := strings.ToLower(strings.TrimSpace(exporter.Format()))
	if format == "" {
		return sferr.New(sferr.CodeInvalidArgument, opRegisterExporter, "exporter format is required")
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	if r.exporters == nil {
		r.exporters = make(map[string]ports.Exporter)
	}
	r.exporters[format] = exporter
	return nil
}

func (r *ExporterRegistry) ByFormat(format string) (ports.Exporter, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	exporter, ok := r.exporters[strings.ToLower(strings.TrimSpace(format))]
	if !ok {
		return nil, sferr.New(sferr.CodeUnsupportedInput, opExporterByFormat, "unsupported exporter format: "+format)
	}

	return exporter, nil
}
