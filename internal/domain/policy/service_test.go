package policy

import (
	"context"
	"strings"
	"testing"

	"github.com/axon/axon/internal/domain/evidence"
)

func TestCompareCategorizesFindingsByFingerprint(t *testing.T) {
	t.Parallel()

	service := Service{}
	current := []evidence.Finding{
		{ID: "new", Identity: evidence.Identity{FingerprintV1: testHash('a')}},
		{ID: "existing", Identity: evidence.Identity{FingerprintV1: testHash('b')}},
	}
	baseline := []evidence.Finding{
		{ID: "old", Identity: evidence.Identity{FingerprintV1: testHash('b')}},
		{ID: "fixed", Identity: evidence.Identity{FingerprintV1: testHash('c')}},
	}

	diff := service.Compare(current, baseline)
	if len(diff.New) != 1 || diff.New[0].ID != "new" {
		t.Fatalf("expected one new finding, got %#v", diff.New)
	}
	if len(diff.Existing) != 1 || diff.Existing[0].ID != "existing" {
		t.Fatalf("expected one existing finding, got %#v", diff.Existing)
	}
	if len(diff.Fixed) != 1 || diff.Fixed[0].ID != "fixed" {
		t.Fatalf("expected one fixed finding, got %#v", diff.Fixed)
	}
}

func TestEvaluateRespectsFailOnNewOnlyAndAllowlist(t *testing.T) {
	t.Parallel()

	service := Service{}
	findings := []evidence.Finding{
		{
			ID: "new-high",
			Severity: evidence.Severity{
				Label: evidence.SeverityHigh,
			},
			Identity: evidence.Identity{
				FingerprintV1: testHash('d'),
			},
		},
		{
			ID: "existing-critical",
			Severity: evidence.Severity{
				Label: evidence.SeverityCritical,
			},
			Identity: evidence.Identity{
				FingerprintV1: testHash('e'),
			},
		},
	}

	diff := BaselineDiff{
		New:      findings[:1],
		Existing: findings[1:],
	}

	decision, err := service.Evaluate(context.Background(), findings, diff, Policy{
		FailOnSeverity: evidence.SeverityCritical,
		FailOnNewOnly:  true,
		Allowlist: []AllowlistEntry{
			{FingerprintV1: strings.Repeat("d", 64)},
		},
	})
	if err != nil {
		t.Fatalf("Evaluate returned error: %v", err)
	}
	if !decision.Passed {
		t.Fatalf("expected policy to pass, got violations %#v", decision.Violations)
	}
	if len(decision.EvaluatedFindings) != 0 {
		t.Fatalf("expected allowlisted new findings to be removed, got %#v", decision.EvaluatedFindings)
	}
}

func testHash(ch byte) evidence.Hash {
	hash, ok := evidence.ParseHash(strings.Repeat(string([]byte{ch}), 64))
	if !ok {
		panic("invalid test hash")
	}

	return hash
}
