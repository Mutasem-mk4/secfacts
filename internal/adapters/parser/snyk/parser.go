package snyk

import (
	"context"
	"encoding/json"
	"path/filepath"
	"strings"

	sferr "github.com/axon/axon/internal/domain/errors"
	"github.com/axon/axon/internal/domain/evidence"
	"github.com/axon/axon/internal/ports"
)

const opParse = "snyk.Parser.Parse"
const opHydrate = "snyk.Parser.Hydrate"

type Parser struct{}

type report struct {
	Vulnerabilities []vulnerability `json:"vulnerabilities"`
	ProjectName     string          `json:"projectName"`
	Path            string          `json:"path"`
}

type vulnerability struct {
	ID          string      `json:"id"`
	Title       string      `json:"title"`
	Description string      `json:"description"`
	Severity    string      `json:"severity"`
	PackageName string      `json:"packageName"`
	Version     string      `json:"version"`
	Identifiers identifiers `json:"identifiers"`
	CVSSScore   float64     `json:"cvssScore"`
	FixedIn     []string    `json:"fixedIn"`
}

type identifiers struct {
	CVE []string `json:"CVE"`
	CWE []string `json:"CWE"`
}

func (Parser) Provider() string {
	return "snyk"
}

func (Parser) Supports(filename string) bool {
	return strings.EqualFold(filepath.Ext(filename), ".json")
}

func (Parser) Parse(ctx context.Context, req ports.ParseRequest, sink ports.FindingSink) error {
	decoder := json.NewDecoder(req.Reader)

	var doc report
	if err := decoder.Decode(&doc); err != nil {
		return sferr.WrapJSON(sferr.CodeParseFailed, opParse, err, req.ReaderAt, "decode snyk report")
	}

	for index, v := range doc.Vulnerabilities {
		if err := ctx.Err(); err != nil {
			return err
		}

		finding := mapVulnerability(req, doc, v)
		meta := ports.ParseMetadata{
			Index: index,
		}

		if err := sink.WriteFinding(ctx, finding, meta); err != nil {
			return err
		}
	}

	return nil
}

func (Parser) Hydrate(ctx context.Context, req ports.HydrateRequest) (evidence.Finding, error) {
	// Snyk hydration usually requires the full report. For now, we return error as we don't store offsets for Snyk yet.
	return evidence.Finding{}, sferr.New(sferr.CodeUnimplemented, opHydrate, "snyk hydration not yet supported")
}

func mapVulnerability(req ports.ParseRequest, doc report, v vulnerability) evidence.Finding {
	return evidence.Finding{
		SchemaVersion: evidence.SchemaVersion,
		Kind:          evidence.KindSCA,
		Title:         v.Title,
		Description:   v.Description,
		Severity: evidence.Severity{
			Label: toSeverityLabel(v.Severity),
			Score: v.CVSSScore,
		},
		Rule: evidence.Rule{
			ID:       v.ID,
			Name:     v.Title,
			Category: "vulnerability",
		},
		Artifact: evidence.Artifact{
			Type: "package",
			Name: v.PackageName,
		},
		Package: &evidence.Package{
			Type:    "dependency",
			Name:    v.PackageName,
			Version: v.Version,
		},
		Vulnerability: &evidence.Vulnerability{
			ID:        v.ID,
			CWE:       v.Identifiers.CWE,
			CVSSScore: v.CVSSScore,
		},
		Source: evidence.SourceRecord{
			Provider:       req.Source.Provider,
			Scanner:        "snyk",
			ScannerVersion: req.Source.ToolVersion,
			FindingID:      v.ID,
		},
	}
}

func toSeverityLabel(value string) evidence.SeverityLabel {
	switch strings.ToLower(value) {
	case "critical":
		return evidence.SeverityCritical
	case "high":
		return evidence.SeverityHigh
	case "medium":
		return evidence.SeverityMedium
	case "low":
		return evidence.SeverityLow
	default:
		return evidence.SeverityInfo
	}
}
