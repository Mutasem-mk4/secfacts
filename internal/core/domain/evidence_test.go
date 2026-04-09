package domain_test

import (
	"github.com/axon/axon/internal/core/domain"
	"testing"
	"time"
)

func TestEvidenceStructure(t *testing.T) {
	t.Parallel()

	ev := domain.Evidence{
		ID:       "test-id-123",
		Provider: "trivy",
		Type:     domain.TypeSCA,
		Vulnerability: domain.Vulnerability{
			ID: "CVE-2024-1000",
		},
		Resource: domain.Resource{
			URI: "pkg:npm/example@1.0.0",
		},
		Severity: domain.Severity{
			Score: 7.5,
			Label: "High",
		},
		Timestamp: time.Now(),
	}

	if ev.ID != "test-id-123" {
		t.Errorf("Expected ID %s, got %s", "test-id-123", ev.ID)
	}

	if ev.Severity.Score != 7.5 {
		t.Errorf("Expected severity score %f, got %f", 7.5, ev.Severity.Score)
	}

	if ev.Type != domain.TypeSCA {
		t.Errorf("Expected type %s, got %s", domain.TypeSCA, ev.Type)
	}
}
