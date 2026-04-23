package normalize

import (
	"context"
	"fmt"
	"math"
	"path/filepath"
	"strconv"
	"strings"

	sferr "github.com/axon/axon/internal/domain/errors"
	"github.com/axon/axon/internal/domain/evidence"
)

const opNormalize = "normalize.Service.Normalize"

type Service struct {
	IdentityBuilder evidence.IdentityBuilder
	Interner        *evidence.Interner
}

func (s Service) Normalize(_ context.Context, finding evidence.Finding) (evidence.Finding, error) {
	if s.IdentityBuilder == nil {
		return evidence.Finding{}, sferr.New(sferr.CodeInvalidConfig, opNormalize, "identity builder is required")
	}

	finding.SchemaVersion = evidence.SchemaVersion
	finding.Kind = normalizeKind(finding.Kind)

	severity, err := normalizeSeverity(finding)
	if err != nil {
		return evidence.Finding{}, sferr.Wrap(sferr.CodeNormalizeFailed, opNormalize, err, "normalize severity")
	}
	finding.Severity = severity

	finding.Rule.ID = strings.TrimSpace(finding.Rule.ID)
	finding.Rule.Name = strings.TrimSpace(finding.Rule.Name)
	finding.Title = strings.TrimSpace(finding.Title)
	finding.Description = strings.TrimSpace(finding.Description)
	finding.PrimaryLocation.URI = normalizeLocationPath(finding.PrimaryLocation.URI)
	for index := range finding.Locations {
		finding.Locations[index].URI = normalizeLocationPath(finding.Locations[index].URI)
	}

	finding.RootCauseHints = appendNormalizedHints(finding)
	s.internFinding(&finding)
	finding.Identity = s.IdentityBuilder.Build(finding)

	return finding, nil
}

func (s Service) internFinding(finding *evidence.Finding) {
	if s.Interner == nil {
		return
	}

	finding.SchemaVersion = s.Interner.Intern(finding.SchemaVersion)
	finding.Kind = evidence.Kind(s.Interner.Intern(string(finding.Kind)))
	finding.Severity.Label = evidence.SeverityLabel(s.Interner.Intern(string(finding.Severity.Label)))
	finding.Severity.Vector = s.Interner.Intern(finding.Severity.Vector)
	finding.Confidence = evidence.Confidence(s.Interner.Intern(string(finding.Confidence)))
	finding.Rule.Category = s.Interner.Intern(finding.Rule.Category)
	finding.Rule.Subcategory = s.Interner.Intern(finding.Rule.Subcategory)
	finding.Artifact.Type = s.Interner.Intern(finding.Artifact.Type)
	finding.Artifact.Namespace = s.Interner.Intern(finding.Artifact.Namespace)
	finding.Source.Provider = s.Interner.Intern(finding.Source.Provider)
	finding.Source.Scanner = s.Interner.Intern(finding.Source.Scanner)
	finding.Source.ScannerVersion = s.Interner.Intern(finding.Source.ScannerVersion)
	if finding.Package != nil {
		finding.Package.Type = s.Interner.Intern(finding.Package.Type)
		finding.Package.Version = s.Interner.Intern(finding.Package.Version)
		finding.Package.FixedVersion = s.Interner.Intern(finding.Package.FixedVersion)
		finding.Package.Language = s.Interner.Intern(finding.Package.Language)
	}
	if finding.Image != nil {
		finding.Image.Registry = s.Interner.Intern(finding.Image.Registry)
		finding.Image.Repository = s.Interner.Intern(finding.Image.Repository)
		finding.Image.Tag = s.Interner.Intern(finding.Image.Tag)
		finding.Image.BaseName = s.Interner.Intern(finding.Image.BaseName)
	}
	if finding.Cloud != nil {
		finding.Cloud.Provider = s.Interner.Intern(finding.Cloud.Provider)
		finding.Cloud.AccountID = s.Interner.Intern(finding.Cloud.AccountID)
		finding.Cloud.Region = s.Interner.Intern(finding.Cloud.Region)
		finding.Cloud.Service = s.Interner.Intern(finding.Cloud.Service)
	}
	if finding.Secret != nil {
		finding.Secret.Type = s.Interner.Intern(finding.Secret.Type)
		finding.Secret.Provider = s.Interner.Intern(finding.Secret.Provider)
	}
	if finding.Vulnerability != nil {
		finding.Vulnerability.CVSSVector = s.Interner.Intern(finding.Vulnerability.CVSSVector)
		finding.Vulnerability.AttackVector = s.Interner.Intern(finding.Vulnerability.AttackVector)
		finding.Vulnerability.Exploitability = s.Interner.Intern(finding.Vulnerability.Exploitability)
	}
}

func normalizeSeverity(finding evidence.Finding) (evidence.Severity, error) {
	score, vector := severityInputs(finding)
	return evidence.NewSeverity(score, vector)
}

func severityInputs(finding evidence.Finding) (float64, string) {
	score := clampScore(finding.Severity.Score)
	vector := strings.TrimSpace(finding.Severity.Vector)
	label := string(finding.Severity.Label)
	if label == "" {
		label = annotationValue(finding, "severity.label")
	}

	if score > 0 {
		return score, vector
	}
	if isInformationalLabel(label) {
		return 0, vector
	}
	if finding.Vulnerability != nil {
		if score := clampScore(finding.Vulnerability.CVSSScore); score >= 0 {
			return score, fallbackVector(vector, finding.Vulnerability.CVSSVector)
		}
	}

	for _, key := range []string{"severity.score", "cvss.score"} {
		if score, ok := annotationScore(finding, key); ok {
			return score, vector
		}
	}
	if strings.TrimSpace(label) != "" {
		return severityScoreFromLabel(label), vector
	}
	if score == 0 {
		return 0, vector
	}

	return severityScoreFromLabel(label), vector
}

func severityScoreFromLabel(label string) float64 {
	switch strings.ToLower(strings.TrimSpace(label)) {
	case "critical":
		return 9
	case "high":
		return 7
	case "medium", "moderate":
		return 5
	case "low":
		return 2
	case "info", "informational", "note":
		return 0
	default:
		return 0
	}
}

func isInformationalLabel(label string) bool {
	switch strings.ToLower(strings.TrimSpace(label)) {
	case "info", "informational", "note":
		return true
	default:
		return false
	}
}

func annotationScore(f evidence.Finding, key string) (float64, bool) {
	raw := annotationValue(f, key)
	if raw == "" {
		return 0, false
	}

	value, err := strconv.ParseFloat(strings.TrimSpace(raw), 64)
	if err != nil {
		return 0, false
	}

	return clampScore(value), true
}

func clampScore(score float64) float64 {
	if math.IsNaN(score) || math.IsInf(score, 0) {
		return -1
	}
	if score < 0 {
		return -1
	}
	if score > 10 {
		return 10
	}

	return score
}

func fallbackVector(primary string, secondary string) string {
	if strings.TrimSpace(primary) != "" {
		return primary
	}

	return strings.TrimSpace(secondary)
}

func normalizeKind(kind evidence.Kind) evidence.Kind {
	switch strings.ToLower(strings.TrimSpace(string(kind))) {
	case string(evidence.KindSAST):
		return evidence.KindSAST
	case string(evidence.KindDAST):
		return evidence.KindDAST
	case string(evidence.KindSCA):
		return evidence.KindSCA
	case string(evidence.KindCloud):
		return evidence.KindCloud
	case string(evidence.KindSecrets):
		return evidence.KindSecrets
	default:
		return kind
	}
}

func appendNormalizedHints(finding evidence.Finding) []evidence.RootCauseHint {
	hints := append([]evidence.RootCauseHint(nil), finding.RootCauseHints...)

	switch finding.Kind {
	case evidence.KindSCA:
		if finding.Package != nil {
			key := finding.Package.Name
			if finding.Package.PackageURL != "" {
				key = finding.Package.PackageURL
			}
			if key != "" {
				hints = append(hints, evidence.RootCauseHint{
					Type:  "dependency",
					Key:   "package",
					Value: key,
				})
			}
		}
	case evidence.KindSAST:
		if finding.Rule.ID != "" && finding.PrimaryLocation.URI != "" {
			hints = append(hints, evidence.RootCauseHint{
				Type:  "code_path",
				Key:   "rule_path",
				Value: fmt.Sprintf("%s|%s", finding.Rule.ID, finding.PrimaryLocation.URI),
			})
		}
	}

	if finding.Image != nil && finding.Image.BaseDigest != "" {
		hints = append(hints, evidence.RootCauseHint{
			Type:  "base_image",
			Key:   "image",
			Value: finding.Image.BaseDigest,
		})
	}

	return deduplicateHints(hints)
}

func deduplicateHints(hints []evidence.RootCauseHint) []evidence.RootCauseHint {
	seen := make(map[evidence.RootCauseHint]struct{}, len(hints))
	result := make([]evidence.RootCauseHint, 0, len(hints))

	for _, hint := range hints {
		if _, exists := seen[hint]; exists {
			continue
		}

		seen[hint] = struct{}{}
		result = append(result, hint)
	}

	return result
}

func normalizeLocationPath(value string) string {
	if strings.TrimSpace(value) == "" {
		return ""
	}

	return strings.ToLower(filepath.ToSlash(strings.TrimSpace(value)))
}

func annotationValue(finding evidence.Finding, key string) string {
	if len(finding.Annotations) == 0 {
		return ""
	}

	return strings.TrimSpace(finding.Annotations[key])
}
