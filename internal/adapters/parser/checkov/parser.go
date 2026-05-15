package checkov

import (
	"context"
	"encoding/json"
	"path/filepath"
	"strings"

	sferr "github.com/axon/axon/internal/domain/errors"
	"github.com/axon/axon/internal/domain/evidence"
	"github.com/axon/axon/internal/ports"
)

const opParse = "checkov.Parser.Parse"
const opHydrate = "checkov.Parser.Hydrate"

type Parser struct{}

type report struct {
	CheckType string  `json:"check_type"`
	Results   results `json:"results"`
}

type results struct {
	FailedChecks []failedCheck `json:"failed_checks"`
}

type failedCheck struct {
	CheckID       string `json:"check_id"`
	CheckName     string `json:"check_name"`
	FilePath      string `json:"file_path"`
	FileLineRange []int  `json:"file_line_range"`
	Resource      string `json:"resource"`
	Severity      string `json:"severity"`
	Description   string `json:"description"`
}

func (Parser) Provider() string {
	return "checkov"
}

func (Parser) Supports(filename string) bool {
	return strings.EqualFold(filepath.Ext(filename), ".json")
}

func (Parser) Parse(ctx context.Context, req ports.ParseRequest, sink ports.FindingSink) error {
	decoder := json.NewDecoder(req.Reader)

	var reports []report
	// Checkov can return a single object or an array of reports
	var raw json.RawMessage
	if err := decoder.Decode(&raw); err != nil {
		return sferr.WrapJSON(sferr.CodeParseFailed, opParse, err, req.ReaderAt, "decode checkov report")
	}

	if strings.HasPrefix(strings.TrimSpace(string(raw)), "[") {
		if err := json.Unmarshal(raw, &reports); err != nil {
			return sferr.WrapJSON(sferr.CodeParseFailed, opParse, err, req.ReaderAt, "unmarshal checkov reports array")
		}
	} else {
		var r report
		if err := json.Unmarshal(raw, &r); err != nil {
			return sferr.WrapJSON(sferr.CodeParseFailed, opParse, err, req.ReaderAt, "unmarshal checkov report object")
		}
		reports = append(reports, r)
	}

	for _, r := range reports {
		for index, check := range r.Results.FailedChecks {
			if err := ctx.Err(); err != nil {
				return err
			}

			finding := mapCheck(req, r, check)
			meta := ports.ParseMetadata{
				Index: index,
				Hint:  r.CheckType,
			}

			if err := sink.WriteFinding(ctx, finding, meta); err != nil {
				return err
			}
		}
	}

	return nil
}

func (Parser) Hydrate(ctx context.Context, req ports.HydrateRequest) (evidence.Finding, error) {
	return evidence.Finding{}, sferr.New(sferr.CodeUnimplemented, opHydrate, "checkov hydration not yet supported")
}

func mapCheck(req ports.ParseRequest, r report, check failedCheck) evidence.Finding {
	startLine := 0
	endLine := 0
	if len(check.FileLineRange) >= 2 {
		startLine = check.FileLineRange[0]
		endLine = check.FileLineRange[1]
	}

	return evidence.Finding{
		SchemaVersion: evidence.SchemaVersion,
		Kind:          evidence.KindCloud,
		Title:         check.CheckName,
		Description:   check.Description,
		Severity: evidence.Severity{
			Label: toSeverityLabel(check.Severity),
		},
		Rule: evidence.Rule{
			ID:       check.CheckID,
			Name:     check.CheckName,
			Category: r.CheckType,
		},
		PrimaryLocation: evidence.Location{
			URI:     check.FilePath,
			Line:    startLine,
			EndLine: endLine,
		},
		Artifact: evidence.Artifact{
			Type: "cloud_resource",
			Name: check.Resource,
		},
		Source: evidence.SourceRecord{
			Provider:       req.Source.Provider,
			Scanner:        "checkov",
			ScannerVersion: req.Source.ToolVersion,
			FindingID:      check.CheckID + ":" + check.Resource,
		},
	}
}

func toSeverityLabel(value string) evidence.SeverityLabel {
	switch strings.ToUpper(value) {
	case "CRITICAL":
		return evidence.SeverityCritical
	case "HIGH":
		return evidence.SeverityHigh
	case "MEDIUM":
		return evidence.SeverityMedium
	case "LOW":
		return evidence.SeverityLow
	default:
		return evidence.SeverityInfo
	}
}
