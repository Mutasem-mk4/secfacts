package services_test

import (
	"context"
	"github.com/axon/axon/internal/core/domain"
	"github.com/axon/axon/internal/core/services"
	"testing"
	"time"
)

func TestShardedNormalizer_DeterministicRouting(t *testing.T) {
	t.Parallel()

	// 1. Setup normalizer with 4 workers
	norm := services.NewShardedNormalizer(4)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	in := make(chan domain.Evidence)
	out, _ := norm.Process(ctx, in)

	// 2. Prepare identical findings from different sources
	finding1 := domain.Evidence{
		ID:       "raw-1",
		Provider: "trivy",
		Type:     domain.TypeSCA,
		Vulnerability: domain.Vulnerability{
			ID: "CVE-2024-0001",
		},
		Resource: domain.Resource{
			URI: "pkg:npm/express@4.17.1",
		},
	}

	finding2 := domain.Evidence{
		ID:       "raw-2",
		Provider: "grype",
		Type:     domain.TypeSCA,
		Vulnerability: domain.Vulnerability{
			ID: "CVE-2024-0001",
		},
		Resource: domain.Resource{
			URI: "pkg:npm/express@4.17.1",
		},
	}

	// 3. Send findings
	go func() {
		in <- finding1
		in <- finding2
		close(in)
	}()

	// 4. Collect results - should be exactly 1 due to deduplication
	count := 0
	for range out {
		count++
	}

	if count != 1 {
		t.Errorf("Expected 1 deduplicated finding, got %d", count)
	}
}

func TestShardedNormalizer_PathNormalization(t *testing.T) {
	t.Parallel()

	norm := services.NewShardedNormalizer(1)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	in := make(chan domain.Evidence)
	out, _ := norm.Process(ctx, in)

	// Findings with different path formats but same logical resource
	f1 := domain.Evidence{
		Vulnerability: domain.Vulnerability{ID: "VULN-1"},
		Resource:      domain.Resource{URI: "./src/app.go"},
	}
	f2 := domain.Evidence{
		Vulnerability: domain.Vulnerability{ID: "VULN-1"},
		Resource:      domain.Resource{URI: "src//app.go"},
	}

	go func() {
		in <- f1
		in <- f2
		close(in)
	}()

	count := 0
	for ev := range out {
		count++
		if ev.Resource.URI != "src/app.go" {
			t.Errorf("Expected normalized path 'src/app.go', got '%s'", ev.Resource.URI)
		}
	}

	if count != 1 {
		t.Errorf("Expected 1 deduplicated finding due to path normalization, got %d", count)
	}
}
