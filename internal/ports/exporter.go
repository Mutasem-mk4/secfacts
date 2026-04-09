package ports

import (
	"context"
	"io"

	"github.com/secfacts/secfacts/internal/domain/evidence"
)

type ExportOptions struct {
	Pretty       bool
	AWSAccountID string
	AWSRegion    string
	ProductARN   string
	GeneratorID  string
}

type FindingIterator interface {
	Next(ctx context.Context) (evidence.Finding, error)
	Close() error
}

type ExportRequest struct {
	Document evidence.Document
	Findings FindingIterator
	Writer   io.Writer
	Options  ExportOptions
}

type Exporter interface {
	Format() string
	Export(ctx context.Context, req ExportRequest) error
}

type SliceFindingIterator struct {
	findings []evidence.Finding
	index    int
}

func NewSliceFindingIterator(findings []evidence.Finding) *SliceFindingIterator {
	return &SliceFindingIterator{findings: findings}
}

func (it *SliceFindingIterator) Next(_ context.Context) (evidence.Finding, error) {
	if it == nil || it.index >= len(it.findings) {
		return evidence.Finding{}, io.EOF
	}

	finding := it.findings[it.index]
	it.index++
	return finding, nil
}

func (it *SliceFindingIterator) Close() error {
	return nil
}
