package app

import (
	"fmt"
	"net"

	"github.com/rs/zerolog"
	"github.com/spf13/cobra"
	"google.golang.org/grpc"

	pb "github.com/axon/axon/api/proto/v1"
	ingress "github.com/axon/axon/internal/adapters/ingress/grpc"
	"github.com/axon/axon/internal/adapters/messaging/nats"
	"github.com/axon/axon/internal/bootstrap"
	"github.com/axon/axon/internal/core/services/cache"
)

func newServeCommand(cfg bootstrap.Config, logger zerolog.Logger) *cobra.Command {
	var port int
	var natsURL string
	var shards int
	var cacheSize int

	cmd := &cobra.Command{
		Use:   "serve",
		Short: "Start the gRPC ingress server to receive security evidence.",
		RunE: func(cmd *cobra.Command, _ []string) error {
			// Initialize NATS Publisher
			publisher, err := nats.NewNATSAdapter(natsURL, shards)
			if err != nil {
				return fmt.Errorf("failed to connect to NATS: %w", err)
			}

			// Initialize Local Deduplication Cache
			dedupeCache := cache.NewLRUCache(cacheSize)

			// Initialize gRPC Server
			lis, err := net.Listen("tcp", fmt.Sprintf(":%d", port))
			if err != nil {
				return fmt.Errorf("failed to listen on port %d: %w", port, err)
			}

			grpcServer := grpc.NewServer()
			ingressServer := ingress.NewIngressServer(publisher, dedupeCache)
			pb.RegisterIngressServiceServer(grpcServer, ingressServer)

			logger.Info().
				Int("port", port).
				Str("nats_url", natsURL).
				Int("shards", shards).
				Msg("starting gRPC ingress server")

			return grpcServer.Serve(lis)
		},
	}

	cmd.Flags().IntVarP(&port, "port", "p", 50051, "gRPC server port")
	cmd.Flags().StringVar(&natsURL, "nats-url", "nats://localhost:4222", "NATS server URL")
	cmd.Flags().IntVar(&shards, "shards", 10, "Number of shards for deterministic routing")
	cmd.Flags().IntVar(&cacheSize, "cache-size", 10000, "Local deduplication LRU cache size")

	return cmd
}
