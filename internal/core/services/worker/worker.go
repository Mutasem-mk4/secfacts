package worker

import (
	"context"
	"fmt"
	"github.com/secfacts/secfacts/internal/core/domain"
	"github.com/secfacts/secfacts/internal/core/ports"
	"github.com/rs/zerolog/log"
)

// Worker orchestrates the sharded processing of security evidence.
type Worker struct {
	subscriber ports.Subscriber
	normalizer ports.Normalizer
	correlator ports.Correlator
	shards     []int
}

// NewWorker creates a new sharded worker.
func NewWorker(sub ports.Subscriber, norm ports.Normalizer, corr ports.Correlator, shards []int) *Worker {
	return &Worker{
		subscriber: sub,
		normalizer: norm,
		correlator: corr,
		shards:     shards,
	}
}

// Start begins the worker's consumption and processing loop.
func (w *Worker) Start(ctx context.Context) error {
	log.Info().Ints("shards", w.shards).Msg("starting worker...")

	// 1. Subscribe to assigned shards
	evChan, subErrChan := w.subscriber.Subscribe(ctx, w.shards)

	// 2. Normalization (Deduplication)
	normChan, normErrChan := w.normalizer.Process(ctx, evChan)

	// 3. Correlation (Reasoning)
	issueChan, corrErrChan := w.correlator.Correlate(ctx, normChan)

	// Consume issues (In worker mode, we might want to push these to a DB or another broker)
	go func() {
		for issue := range issueChan {
			log.Info().
				Str("id", issue.ID).
				Float32("score", issue.Severity.Score).
				Msg("correlated issue processed")
			// TODO: Final Aggregate Store integration
		}
	}()

	// Error handling
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case err := <-subErrChan:
			if err != nil {
				return fmt.Errorf("subscriber error: %w", err)
			}
		case err := <-normErrChan:
			if err != nil {
				return fmt.Errorf("normalizer error: %w", err)
			}
		case err := <-corrErrChan:
			if err != nil {
				return fmt.Errorf("correlator error: %w", err)
			}
		}
	}
}
