package baseline

import (
	"context"
	"os"

	sferr "github.com/axon/axon/internal/domain/errors"
	"github.com/axon/axon/internal/domain/evidence"
	"github.com/axon/axon/internal/ports"
)

const opLoad = "baseline.LoadIEMJSON"

func LoadIEMJSON(ctx context.Context, path string, parser ports.Parser) (evidence.Document, error) {
	if parser == nil {
		return evidence.Document{}, sferr.New(sferr.CodeInvalidConfig, opLoad, "parser is required")
	}

	file, err := os.Open(path)
	if err != nil {
		return evidence.Document{}, sferr.Wrap(sferr.CodeIO, opLoad, err, "open baseline file")
	}
	defer file.Close()

	findings := make([]evidence.Finding, 0, 128)
	sink := sinkFunc(func(_ context.Context, finding evidence.Finding) error {
		findings = append(findings, finding)
		return nil
	})

	err = parser.Parse(ctx, ports.ParseRequest{
		Filename: path,
		Reader:   file,
		Source: evidence.SourceDescriptor{
			Provider: "axon-baseline",
			Format:   "json",
		},
	}, sink)
	if err != nil {
		return evidence.Document{}, sferr.Wrap(sferr.CodeBaselineFailed, opLoad, err, "parse baseline")
	}

	return evidence.Document{
		SchemaVersion: evidence.SchemaVersion,
		Findings:      findings,
		Summary: evidence.Summary{
			TotalFindings:  len(findings),
			UniqueFindings: len(findings),
		},
	}, nil
}

type sinkFunc func(context.Context, evidence.Finding) error

func (f sinkFunc) WriteFinding(ctx context.Context, finding evidence.Finding, _ ports.ParseMetadata) error {
	return f(ctx, finding)
}
