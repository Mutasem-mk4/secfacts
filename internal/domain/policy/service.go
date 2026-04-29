package policy

import (
	"context"
	"slices"
	"strings"
	"time"

	sferr "github.com/axon/axon/internal/domain/errors"
	"github.com/axon/axon/internal/domain/evidence"
)

const opEvaluate = "policy.Service.Evaluate"

type Status string

const (
	StatusExisting Status = "existing"
	StatusNew      Status = "new"
	StatusFixed    Status = "fixed"
)

type AllowlistEntry struct {
	FingerprintV1   string     `yaml:"fingerprint_v1" json:"fingerprint_v1"`
	RuleID          string     `yaml:"rule_id" json:"rule_id"`
	VulnerabilityID string     `yaml:"vulnerability_id" json:"vulnerability_id"`
	PackageName     string     `yaml:"package_name" json:"package_name"`
	Path            string     `yaml:"path" json:"path"`
	Reason          string     `yaml:"reason" json:"reason"`
	ExpiresAt       *time.Time `yaml:"expires_at" json:"expires_at"`
}

type Policy struct {
	FailOnSeverity     evidence.SeverityLabel         `yaml:"fail_on_severity" json:"fail_on_severity"`
	FailOnNewOnly      bool                           `yaml:"fail_on_new_only" json:"fail_on_new_only"`
	MaxCountThresholds map[evidence.SeverityLabel]int `yaml:"max_count_thresholds" json:"max_count_thresholds"`
	Allowlist          []AllowlistEntry               `yaml:"allowlist" json:"allowlist"`
}

type BaselineDiff struct {
	New      []evidence.Finding
	Existing []evidence.Finding
	Fixed    []evidence.Finding
}

type Decision struct {
	Passed             bool
	Violations         []Violation
	NewFindings        []evidence.Finding
	ExistingFindings   []evidence.Finding
	FixedFindings      []evidence.Finding
	EvaluatedFindings  []evidence.Finding
	FailedFindingCount int
}

type Violation struct {
	Code    string
	Message string
}

type Service struct{}

func (Service) Compare(current []evidence.Finding, baseline []evidence.Finding) BaselineDiff {
	seenBaseline := make(map[evidence.Hash]evidence.Finding, len(baseline))
	// ⚡ Bolt: Iterate via index to prevent expensive copy of evidence.Finding
	for i := range baseline {
		finding := &baseline[i]
		if finding.Identity.FingerprintV1.IsZero() {
			continue
		}
		seenBaseline[finding.Identity.FingerprintV1] = *finding
	}

	diff := BaselineDiff{
		New:      make([]evidence.Finding, 0, len(current)),
		Existing: make([]evidence.Finding, 0, len(current)),
		Fixed:    make([]evidence.Finding, 0, len(baseline)),
	}

	seenCurrent := make(map[evidence.Hash]struct{}, len(current))
	// ⚡ Bolt: Iterate via index to prevent expensive copy of evidence.Finding
	for i := range current {
		finding := &current[i]
		fingerprint := finding.Identity.FingerprintV1
		if fingerprint.IsZero() {
			diff.New = append(diff.New, *finding)
			continue
		}

		seenCurrent[fingerprint] = struct{}{}
		if _, exists := seenBaseline[fingerprint]; exists {
			diff.Existing = append(diff.Existing, *finding)
			continue
		}

		diff.New = append(diff.New, *finding)
	}

	for fingerprint, finding := range seenBaseline {
		if _, exists := seenCurrent[fingerprint]; exists {
			continue
		}
		diff.Fixed = append(diff.Fixed, finding)
	}

	return diff
}

func (Service) Evaluate(_ context.Context, findings []evidence.Finding, diff BaselineDiff, policy Policy) (Decision, error) {
	if findings == nil {
		return Decision{}, sferr.New(sferr.CodeInvalidArgument, opEvaluate, "findings must not be nil")
	}

	evaluated := findings
	if policy.FailOnNewOnly {
		evaluated = diff.New
	}

	filtered := make([]evidence.Finding, 0, len(evaluated))
	// ⚡ Bolt: Iterate via index to prevent expensive copy of evidence.Finding
	for i := range evaluated {
		finding := &evaluated[i]
		if isAllowlisted(policy.Allowlist, finding) { // Optimization: pass by reference to avoid copy
			continue
		}
		filtered = append(filtered, *finding)
	}

	violations := make([]Violation, 0)
	if threshold := normalizeSeverityLabel(policy.FailOnSeverity); threshold != "" {
		count := 0
		// ⚡ Bolt: Iterate via index to prevent expensive copy of evidence.Finding
	for i := range filtered {
			finding := &filtered[i]
			if meetsSeverityThreshold(finding.Severity.Label, threshold) {
				count++
			}
		}
		if count > 0 {
			violations = append(violations, Violation{
				Code:    "fail_on_severity",
				Message: "findings meet or exceed configured severity threshold",
			})
		}
	}

	if len(policy.MaxCountThresholds) > 0 {
		counts := countBySeverity(filtered)
		for label, limit := range policy.MaxCountThresholds {
			if limit < 0 {
				continue
			}

			normalized := normalizeSeverityLabel(label)
			if counts[normalized] > limit {
				violations = append(violations, Violation{
					Code:    "max_count_threshold",
					Message: "finding count exceeds configured threshold for " + string(normalized),
				})
			}
		}
	}

	return Decision{
		Passed:             len(violations) == 0,
		Violations:         violations,
		NewFindings:        slices.Clone(diff.New),
		ExistingFindings:   slices.Clone(diff.Existing),
		FixedFindings:      slices.Clone(diff.Fixed),
		EvaluatedFindings:  filtered,
		FailedFindingCount: len(filtered),
	}, nil
}

func isAllowlisted(entries []AllowlistEntry, finding *evidence.Finding) bool {
	now := time.Now().UTC()
	for _, entry := range entries {
		if entry.ExpiresAt != nil && entry.ExpiresAt.Before(now) {
			continue
		}
		if entry.FingerprintV1 != "" {
			fingerprint, ok := evidence.ParseHash(entry.FingerprintV1)
			if ok && fingerprint == finding.Identity.FingerprintV1 {
				return true
			}
		}
		if entry.RuleID != "" && entry.RuleID == finding.Rule.ID {
			return true
		}
		if entry.VulnerabilityID != "" && finding.Vulnerability != nil && entry.VulnerabilityID == finding.Vulnerability.ID {
			return true
		}
		if entry.PackageName != "" && finding.Package != nil && entry.PackageName == finding.Package.Name {
			return true
		}
		if entry.Path != "" && entry.Path == finding.PrimaryLocation.URI {
			return true
		}
	}

	return false
}

func countBySeverity(findings []evidence.Finding) map[evidence.SeverityLabel]int {
	counts := make(map[evidence.SeverityLabel]int, 5)
	// ⚡ Bolt: Iterate via index to prevent expensive copy of evidence.Finding
	for i := range findings {
		finding := &findings[i]
		counts[normalizeSeverityLabel(finding.Severity.Label)]++
	}

	return counts
}

func meetsSeverityThreshold(actual evidence.SeverityLabel, threshold evidence.SeverityLabel) bool {
	return severityRank(normalizeSeverityLabel(actual)) >= severityRank(normalizeSeverityLabel(threshold))
}

func severityRank(label evidence.SeverityLabel) int {
	switch normalizeSeverityLabel(label) {
	case evidence.SeverityCritical:
		return 4
	case evidence.SeverityHigh:
		return 3
	case evidence.SeverityMedium:
		return 2
	case evidence.SeverityLow:
		return 1
	default:
		return 0
	}
}

func normalizeSeverityLabel(label evidence.SeverityLabel) evidence.SeverityLabel {
	switch strings.ToLower(strings.TrimSpace(string(label))) {
	case string(evidence.SeverityCritical):
		return evidence.SeverityCritical
	case string(evidence.SeverityHigh):
		return evidence.SeverityHigh
	case string(evidence.SeverityMedium):
		return evidence.SeverityMedium
	case string(evidence.SeverityLow):
		return evidence.SeverityLow
	case "":
		return ""
	default:
		return evidence.SeverityInfo
	}
}
