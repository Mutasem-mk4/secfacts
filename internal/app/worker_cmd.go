package app

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/rs/zerolog"
	"github.com/spf13/cobra"

	"github.com/secfacts/secfacts/internal/adapters/messaging/nats"
	"github.com/secfacts/secfacts/internal/bootstrap"
	"github.com/secfacts/secfacts/internal/core/services"
	"github.com/secfacts/secfacts/internal/core/services/worker"
)

func newWorkerCommand(cfg bootstrap.Config, logger zerolog.Logger) *cobra.Command {
	var natsURL string
	var totalShards int
	var assignedShardsStr string

	cmd := &cobra.Command{
		Use:   "worker",
		Short: "Start a sharded worker to process security evidence from NATS.",
		RunE: func(cmd *cobra.Command, _ []string) error {
			// Parse assigned shards
			shards, err := parseShards(assignedShardsStr)
			if err != nil {
				return err
			}

			// Initialize NATS Subscriber
			subscriber, err := nats.NewNATSAdapter(natsURL, totalShards)
			if err != nil {
				return fmt.Errorf("failed to connect to NATS: %w", err)
			}

			// Initialize Processing Pipeline Components
			// Note: These should ideally be reused from the existing usecase services
			// For simplicity, we re-initialize here for now.
			normalizer := &services.Pipeline{} // Placeholder, needs actual normalizer service
			correlator := &services.Pipeline{} // Placeholder, needs actual correlator service

			w := worker.NewWorker(subscriber, normalizer, correlator, shards)

			logger.Info().
				Str("nats_url", natsURL).
				Ints("assigned_shards", shards).
				Msg("starting sharded worker")

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
