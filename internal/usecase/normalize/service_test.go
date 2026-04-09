package normalize

import (
	"context"
	"testing"

	"github.com/axon/axon/internal/domain/evidence"
)

func TestNormalizeSeverityUsesCVSSAndLabels(t *testing.T) {
	t.Parallel()

	service := Service{
		IdentityBuilder: evidence.DefaultIdentityBuilder{},
	}

	finding, err := service.Normalize(context.Background(), evidence.Finding{
		Kind: evidence.KindSCA,
		Severity: evidence.Severity{
			Label: evidence.SeverityHigh,
		},
		Vulnerability: &evidence.Vulnerability{
			ID:        "CVE-2024-0001",
			CVSSScore: 8.2,
		},
		Package: &evidence.Package{
			Name:       "openssl",
			Version:    "1.0.2",
			PackageURL: "pkg:apk/alpine/openssl@1.0.2",
		},
	})
	if err != nil {
		t.Fatalf("Normalize returned error: %v", err)
	}

	if finding.Severity.Score != 8.2 {
		t.Fatalf("expected severity score 8.2, got %v", finding.Severity.Score)
	}

	sastFinding, err := service.Normalize(context.Background(), evidence.Finding{
		Kind: evidence.KindSAST,
		Severity: evidence.Severity{
			Label: evidence.SeverityMedium,
		},
		Rule: evidence.Rule{
			ID: "go.sql.injection",
		},
		PrimaryLocation: evidence.Location{
			URI:  "internal/repository/user.go",
			Line: 44,
		},
	})
	if err != nil {
		t.Fatalf("Normalize returned error: %v", err)
	}

	if sastFinding.Severity.Score != 5 {
		t.Fatalf("expected severity score 5, got %v", sastFinding.Severity.Score)
	}
}
