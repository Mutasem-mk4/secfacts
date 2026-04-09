package ports

import (
	"context"
	"io"

	"github.com/secfacts/secfacts/internal/domain/evidence"
)

type ParseRequest struct {
	Source   evidence.SourceDescriptor
	Filename string
	Reader   io.Reader
}

type ParseMetadata struct {
	Range   evidence.ByteOffsetRange
	Hint    string
	Index   int
	Context []byte
}

type HydrateRequest struct {
	Source   evidence.SourceDescriptor
	Filename string
	Reader   io.ReaderAt
	Meta     ParseMetadata
}

type FindingSink interface {
	WriteFinding(ctx context.Context, finding evidence.Finding, meta ParseMetadata) error
}

type Parser interface {
	Provider() string
	Supports(filename string) bool
	Parse(ctx context.Context, req ParseRequest, sink FindingSink) error
	Hydrate(ctx context.Context, req HydrateRequest) (evidence.Finding, error)
}
