package gitleaks

import (
	"context"
	"encoding/json"
	"io"
	"path/filepath"
	"strings"

	sferr "github.com/axon/axon/internal/domain/errors"
	"github.com/axon/axon/internal/domain/evidence"
	"github.com/axon/axon/internal/ports"
)

const opParse = "gitleaks.Parser.Parse"
const opHydrate = "gitleaks.Parser.Hydrate"

type Parser struct{}

type leak struct {
	Description string `json:"Description"`
	StartLine   int    `json:"StartLine"`
	EndLine     int    `json:"EndLine"`
	Match       string `json:"Match"`
	Secret      string `json:"Secret"`
	File        string `json:"File"`
	RuleID      string `json:"RuleID"`
	Fingerprint string `json:"Fingerprint"`
}

func (Parser) Provider() string {
	return "gitleaks"
}

func (Parser) Supports(filename string) bool {
	return strings.EqualFold(filepath.Ext(filename), ".json")
}

func (Parser) Parse(ctx context.Context, req ports.ParseRequest, sink ports.FindingSink) error {
	decoder := json.NewDecoder(req.Reader)

	token, err := decoder.Token()
	if err != nil {
		if err == io.EOF {
			return nil
		}
		return sferr.WrapJSON(sferr.CodeParseFailed, opParse, err, req.ReaderAt, "read gitleaks opening token")
	}

	delim, ok := token.(json.Delim)
	if !ok || delim != '[' {
		return sferr.New(sferr.CodeUnsupportedInput, opParse, "gitleaks report must be a JSON array")
	}

	for index := 0; decoder.More(); index++ {
		if err := ctx.Err(); err != nil {
			return err
		}

		start := decoder.InputOffset()
		var item leak
		if err := decoder.Decode(&item); err != nil {
			return sferr.WrapJSON(sferr.CodeParseFailed, opParse, err, req.ReaderAt, "decode leak")
		}

		finding := mapLeak(req, item)
		meta := ports.ParseMetadata{
			Range: evidence.ByteOffsetRange{
				Start: start,
				End:   decoder.InputOffset(),
			},
			Index: index,
		}

		if err := sink.WriteFinding(ctx, finding, meta); err != nil {
			return err
		}
	}

	if _, err := decoder.Token(); err != nil {
		return sferr.WrapJSON(sferr.CodeParseFailed, opParse, err, req.ReaderAt, "read gitleaks closing token")
	}

	return nil
}

func (Parser) Hydrate(ctx context.Context, req ports.HydrateRequest) (evidence.Finding, error) {
	// For simplicity, we re-parse the section. In a full implementation, we'd use the offset.
	section := io.NewSectionReader(req.Reader, req.Meta.Range.Start, req.Meta.Range.Len())
	var item leak
	if err := json.NewDecoder(section).Decode(&item); err != nil {
		return evidence.Finding{}, sferr.WrapJSON(sferr.CodeParseFailed, opHydrate, err, req.Reader, "decode hydrated leak")
	}

	return mapLeak(ports.ParseRequest{Source: req.Source, Filename: req.Filename}, item), nil
}

func mapLeak(req ports.ParseRequest, item leak) evidence.Finding {
	return evidence.Finding{
		SchemaVersion: evidence.SchemaVersion,
		Kind:          evidence.KindSecrets,
		Title:         item.Description,
		Description:   "Secret detected in " + item.File,
		Severity: evidence.Severity{
			Label: evidence.SeverityHigh, // Gitleaks doesn't provide severity, default to High
		},
		Rule: evidence.Rule{
			ID:       item.RuleID,
			Name:     item.Description,
			Category: "secret",
		},
		PrimaryLocation: evidence.Location{
			URI:     item.File,
			Line:    item.StartLine,
			EndLine: item.EndLine,
		},
		Artifact: evidence.Artifact{
			Type: "file",
			Name: item.File,
		},
		Secret: &evidence.Secret{
			Type:        "secret",
			Provider:    "gitleaks",
			Fingerprint: item.Fingerprint,
			Redacted:    redactSecret(item.Secret),
		},
		Source: evidence.SourceRecord{
			Provider:       req.Source.Provider,
			Scanner:        "gitleaks",
			ScannerVersion: req.Source.ToolVersion,
			FindingID:      item.Fingerprint,
		},
	}
}

func redactSecret(value string) string {
	if len(value) <= 6 {
		return "***"
	}
	return value[:3] + "***" + value[len(value)-3:]
}
