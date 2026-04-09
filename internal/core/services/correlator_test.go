package services_test

import (
	"context"
	"testing"
	"time"

	"github.com/axon/axon/internal/core/domain"
	"github.com/axon/axon/internal/core/services"
)

func TestCorrelatorService_ContextAwareScoring(t *testing.T) {
	t.Parallel()

	cor := services.NewCorrelatorService()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	in := make(chan domain.Evidence)
	out, _ := cor.Correlate(ctx, in)

	// Findings: A vulnerability AND a public exposure on the same bucket.
	f1 := domain.Evidence{
		Type:          domain.TypeSCA,
		Vulnerability: domain.Vulnerability{ID: "CVE-2024-PKG"},
		Resource:      domain.Resource{URI: "arn:aws:s3:::my-vulnerable-bucket", Name: "my-vulnerable-bucket"},
		Severity:      domain.Severity{Score: 8.0, Label: "High"},
	}
	f2 := domain.Evidence{
		Type:     domain.TypeCloud,
		Resource: domain.Resource{URI: "arn:aws:s3:::my-vulnerable-bucket", Name: "my-vulnerable-bucket"},
		Severity: domain.Severity{Score: 5.0, Label: "Medium"},
		Details:  map[string]string{"issue": "Publicly Exposed"},
	}

	go func() {
		in <- f1
		in <- f2
		close(in)
	}()

	issue := <-out

	// Check if weighted score reflects compound risk (8.0 * 1.5 multiplier)
	if issue.Severity.Score <= 8.0 {
		t.Errorf("Expected context-aware score to be higher than base 8.0, got %f", issue.Severity.Score)
	}

	if issue.Severity.Score > 10.0 {
		t.Errorf("Final score should be capped at 10.0, got %f", issue.Severity.Score)
	}

	if issue.Type != "Exposed Vulnerable Asset" {
		t.Errorf("Expected logical type 'Exposed Vulnerable Asset', got %s", issue.Type)
	}
}

func TestCorrelatorService_Grouping(t *testing.T) {
	t.Parallel()

	cor := services.NewCorrelatorService()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	in := make(chan domain.Evidence)
	out, _ := cor.Correlate(ctx, in)

	// Findings: 3 CVEs on same package.
	go func() {
		for i := 0; i < 3; i++ {
			in <- domain.Evidence{
				Type:     domain.TypeSCA,
				Resource: domain.Resource{URI: "pkg:npm/express@4.17.1", Name: "express"},
				Severity: domain.Severity{Score: 5.0, Label: "Medium"},
			}
		}
		close(in)
	}()

	issue := <-out
	if len(issue.Findings) != 3 {
		t.Errorf("Expected 3 findings in the correlated issue, got %d", len(issue.Findings))
	}

	if issue.Target.URI != "pkg:npm/express@4.17.1" {
		t.Errorf("Expected target 'pkg:npm/express@4.17.1', got %s", issue.Target.URI)
	}
}
