package ports

import (
	"context"

	"github.com/axon/axon/internal/domain/evidence"
)

type Normalizer interface {
	Normalize(ctx context.Context, finding evidence.Finding) (evidence.Finding, error)
}

type Deduplicator interface {
	Fingerprint(ctx context.Context, finding evidence.Finding) (evidence.Identity, error)
}

type Correlator interface {
	Correlate(ctx context.Context, findings []evidence.Finding) ([]evidence.RootCauseCluster, error)
}
