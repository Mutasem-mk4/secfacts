package app

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/rs/zerolog"
	"github.com/spf13/cobra"

	"github.com/axon/axon/internal/adapters/messaging/nats"
	"github.com/axon/axon/internal/adapters/sink"
	"github.com/axon/axon/internal/bootstrap"
	"github.com/axon/axon/internal/core/ports"
	"github.com/axon/axon/internal/core/services"
	"github.com/axon/axon/internal/core/services/worker"
	sferr "github.com/axon/axon/internal/domain/errors"
)

func newWorkerCommand(cfg bootstrap.Config, logger zerolog.Logger) *cobra.Command {
	var natsURL string
	var totalShards int
	var assignedShardsStr string

	cmd := &cobra.Command{
		Use:   "worker",
		Short: "Start a sharded worker to process security evidence from NATS.",
		RunE: func(cmd *cobra.Command, _ []string) error {
			shards, err := parseShards(assignedShardsStr)
			if err != nil {
				return err
			}

			logger.Info().
				Str("nats_url", natsURL).
				Int("total_shards", totalShards).
				Ints("assigned_shards", shards).
				Msg("starting worker...")

			// 1. Messaging Adapter
			natsAdapter, err := nats.NewNATSAdapter(natsURL, totalShards)
			if err != nil {
				return sferr.Wrap(sferr.CodeInternal, "worker", err, "initialize NATS adapter")
			}

			// 2. Services
			normalizer := services.NewShardedNormalizer(cfg.Workers)
			correlator := &services.CorrelatorService{}

			// 3. Sinks (Integrations)
			sinks := []ports.Sink{
				sink.NewSlackSink(),
				sink.NewJiraSink(),
			}

			// 4. Worker Orchestrator
			w := worker.NewWorker(natsAdapter, normalizer, correlator, shards, sinks...)

			return w.Start(cmd.Context())
		},
	}

	cmd.Flags().StringVar(&natsURL, "nats-url", "nats://localhost:4222", "NATS server URL")
	cmd.Flags().IntVar(&totalShards, "total-shards", 10, "Total number of shards used in the system")
	cmd.Flags().StringVar(&assignedShardsStr, "shards", "0", "Comma-separated list of assigned shard IDs")

	return cmd
}

func parseShards(s string) ([]int, error) {
	parts := strings.Split(s, ",")
	res := make([]int, 0, len(parts))
	for _, p := range parts {
		id, err := strconv.Atoi(strings.TrimSpace(p))
		if err != nil {
			return nil, fmt.Errorf("invalid shard ID '%s': %w", p, err)
		}
		res = append(res, id)
	}
	return res, nil
}
