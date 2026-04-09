package services

import (
	"context"
	"fmt"
	"hash/fnv"

	"github.com/axon/axon/internal/core/domain"
	"github.com/axon/axon/internal/core/ports"
)

// CorrelatorService implements the ports.Correlator interface.
type CorrelatorService struct{}

// NewCorrelatorService creates a new instance of CorrelatorService.
func NewCorrelatorService() *CorrelatorService {
	return &CorrelatorService{}
}

// Correlate implements the grouping and reasoning logic.
func (c *CorrelatorService) Correlate(ctx context.Context, in <-chan domain.Evidence) (<-chan domain.Issue, <-chan error) {
	out := make(chan domain.Issue)
	errChan := make(chan error, 1)

	go func() {
		defer close(out)
		defer close(errChan)

		// Group evidence by Resource URI
		groups := make(map[string][]*domain.Evidence)

		for ev := range in {
			// To maintain pointers, we need to create a copy in the heap
			evCopy := ev
			groups[ev.Resource.URI] = append(groups[ev.Resource.URI], &evCopy)
		}

		// Process groups to generate Issues
		for uri, findings := range groups {
			issue := c.generateIssue(uri, findings)
			select {
			case out <- issue:
			case <-ctx.Done():
				return
			}
		}
	}()

	return out, errChan
}

func (c *CorrelatorService) generateIssue(uri string, findings []*domain.Evidence) domain.Issue {
	if len(findings) == 0 {
		return domain.Issue{}
	}

	// Use the first finding for base resource info
	base := findings[0]

	issue := domain.Issue{
		ID:       c.hashID(uri),
		Target:   base.Resource,
		Findings: findings,
	}

	// 1. Determine Issue Type & Remediation
	c.reasonRootCause(&issue)

	// 2. Context-Aware Severity Scoring
	issue.Severity = c.calculateWeightedSeverity(findings)

	return issue
}

func (c *CorrelatorService) reasonRootCause(issue *domain.Issue) {
	types := make(map[domain.FindingType]bool)
	for _, f := range issue.Findings {
		types[f.Type] = true
	}

	count := len(issue.Findings)

	// Reasoning Logic
	switch {
	case types[domain.TypeSCA] && types[domain.TypeCloud]:
		issue.Type = "Exposed Vulnerable Asset"
		issue.Remediation = "CRITICAL: A vulnerable dependency is detected on a potentially exposed cloud resource. Patch immediately and restrict access."
	case types[domain.TypeSCA] && len(types) == 1:
		issue.Type = "Package Vulnerability Aggregation"
		issue.Remediation = fmt.Sprintf("Upgrade package %s to resolve %d known vulnerabilities.", issue.Target.Name, count)
	case types[domain.TypeCloud]:
		issue.Type = "Infrastructure Misconfiguration"
		issue.Remediation = fmt.Sprintf("Review IAM and Network policies for %s. Apply least-privilege principles.", issue.Target.URI)
	default:
		issue.Type = "Multi-Vector Security Issue"
		issue.Remediation = "Review all findings on this resource for a holistic security fix."
	}
}

func (c *CorrelatorService) calculateWeightedSeverity(findings []*domain.Evidence) domain.Severity {
	var maxScore float32
	var label string
	types := make(map[domain.FindingType]bool)

	for _, f := range findings {
		if f.Severity.Score > maxScore {
			maxScore = f.Severity.Score
			label = f.Severity.Label
		}
		types[f.Type] = true
	}

	// Risk Multipliers
	multiplier := float32(1.0)

	// Compound Risk: Vulnerability + Exposure
	if types[domain.TypeSCA] && types[domain.TypeCloud] {
		multiplier = 1.5
	} else if len(findings) > 5 {
		// High Volume of findings on one asset
		multiplier = 1.2
	}

	finalScore := maxScore * multiplier
	if finalScore > 10.0 {
		finalScore = 10.0
	}

	return domain.Severity{
		Score: finalScore,
		Label: label, // Labels should ideally be recalculated, but for now we take the max label
	}
}

func (c *CorrelatorService) hashID(s string) string {
	h := fnv.New64a()
	_, _ = h.Write([]byte(s))
	return fmt.Sprintf("%x", h.Sum(nil))
}

// Ensure interface compliance
var _ ports.Correlator = (*CorrelatorService)(nil)
