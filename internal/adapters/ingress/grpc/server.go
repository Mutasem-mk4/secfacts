package grpc

import (
	"fmt"
	"io"

	pb "github.com/axon/axon/api/proto/v1"
	"github.com/axon/axon/internal/core/domain"
	"github.com/axon/axon/internal/core/ports"
	"github.com/axon/axon/internal/core/services/cache"
	"github.com/rs/zerolog/log"
)

// IngressServer implements the IngressService gRPC server.
type IngressServer struct {
	pb.UnimplementedIngressServiceServer
	publisher ports.Publisher
	cache     *cache.LRUCache
}

// NewIngressServer creates a new gRPC ingress server.
func NewIngressServer(pub ports.Publisher, dedupeCache *cache.LRUCache) *IngressServer {
	return &IngressServer{
		publisher: pub,
		cache:     dedupeCache,
	}
}

// IngestStream handles bi-directional streaming of evidence from runners.
func (s *IngressServer) IngestStream(stream pb.IngressService_IngestStreamServer) error {
	ctx := stream.Context()

	for {
		req, err := stream.Recv()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return fmt.Errorf("recv: %w", err)
		}

		ev := req.GetEvidence()
		if ev == nil {
			continue
		}

		// Local Deduplication (Optimized)
		if s.cache.Add(ev.Id) {
			// Already seen recently, acknowledge as accepted (already exists)
			if err := stream.Send(&pb.IngestResponse{Id: ev.Id, Accepted: true}); err != nil {
				return fmt.Errorf("send: %w", err)
			}
			continue
		}

		// Convert Proto to Domain Model
		domainEv := toDomain(ev)

		// Publish to NATS
		if err := s.publisher.Publish(ctx, domainEv); err != nil {
			log.Error().Err(err).Str("id", domainEv.ID).Msg("failed to publish to NATS")
			if err := stream.Send(&pb.IngestResponse{Id: ev.Id, Accepted: false}); err != nil {
				return fmt.Errorf("send: %w", err)
			}
			continue
		}

		// Acknowledge receipt
		if err := stream.Send(&pb.IngestResponse{Id: ev.Id, Accepted: true}); err != nil {
			return fmt.Errorf("send: %w", err)
		}
	}
}

// toDomain converts a proto Evidence message to a domain.Evidence struct.
// Note: This requires proper conversion logic for all fields.
func toDomain(p *pb.Evidence) domain.Evidence {
	var loc *domain.Location
	if p.Location != nil {
		loc = &domain.Location{
			Path:      p.Location.Path,
			StartLine: int(p.Location.StartLine),
			StartCol:  int(p.Location.StartCol),
			EndLine:   int(p.Location.EndLine),
			EndCol:    int(p.Location.EndCol),
			Snippet:   p.Location.Snippet,
		}
	}

	return domain.Evidence{
		ID:       p.Id,
		Provider: p.Provider,
		Type:     domain.FindingType(p.Type.String()),
		Vulnerability: domain.Vulnerability{
			ID:          p.Vulnerability.Id,
			Description: p.Vulnerability.Description,
			CWE:         p.Vulnerability.Cwe,
			Aliases:     p.Vulnerability.Aliases,
		},
		Resource: domain.Resource{
			URI:     p.Resource.Uri,
			Name:    p.Resource.Name,
			Version: p.Resource.Version,
			Type:    p.Resource.Type,
		},
		Location: loc,
		Severity: domain.Severity{
			Score:  p.Severity.Score,
			Label:  p.Severity.Label,
			Vector: p.Severity.Vector,
		},
		Details:   p.Details,
		Timestamp: p.Timestamp.AsTime(),
	}
}
