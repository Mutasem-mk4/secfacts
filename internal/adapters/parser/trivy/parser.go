package trivy

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"path/filepath"
	"strings"

	sferr "github.com/axon/axon/internal/domain/errors"
	"github.com/axon/axon/internal/domain/evidence"
	"github.com/axon/axon/internal/ports"
)

const opParse = "trivy.Parser.Parse"
const opHydrate = "trivy.Parser.Hydrate"

const (
	hydrateVulnerability = "trivy:vulnerability"
	hydrateSecret        = "trivy:secret"
)

type Parser struct{}

type report struct {
	ArtifactName string         `json:"ArtifactName"`
	ArtifactType string         `json:"ArtifactType"`
	Metadata     reportMetadata `json:"Metadata"`
	Results      []result       `json:"Results"`
}

type reportMetadata struct {
	ImageID string `json:"ImageID"`
	DiffID  string `json:"DiffID"`
}

type reportContext struct {
	ArtifactName string         `json:"ArtifactName"`
	ArtifactType string         `json:"ArtifactType"`
	Metadata     reportMetadata `json:"Metadata"`
}

type result struct {
	Target          string          `json:"Target"`
	Class           string          `json:"Class"`
	Type            string          `json:"Type"`
	Vulnerabilities []vulnerability `json:"Vulnerabilities"`
	Secrets         []secret        `json:"Secrets"`
}

type vulnerability struct {
	VulnerabilityID  string   `json:"VulnerabilityID"`
	PkgName          string   `json:"PkgName"`
	InstalledVersion string   `json:"InstalledVersion"`
	FixedVersion     string   `json:"FixedVersion"`
	Severity         string   `json:"Severity"`
	Title            string   `json:"Title"`
	Description      string   `json:"Description"`
	PrimaryURL       string   `json:"PrimaryURL"`
	References       []string `json:"References"`
	CweIDs           []string `json:"CweIDs"`
	PkgIdentifier    pkgID    `json:"PkgIdentifier"`
	CVSS             cvssMap  `json:"CVSS"`
}

type pkgID struct {
	PURL string `json:"PURL"`
}

type cvssMap map[string]cvss

type cvss struct {
	V3Score  float64 `json:"V3Score"`
	V3Vector string  `json:"V3Vector"`
}

type secret struct {
	RuleID      string `json:"RuleID"`
	Category    string `json:"Category"`
	Severity    string `json:"Severity"`
	Title       string `json:"Title"`
	Match       string `json:"Match"`
	StartLine   int    `json:"StartLine"`
	EndLine     int    `json:"EndLine"`
	Fingerprint string `json:"Fingerprint"`
}

func (Parser) Provider() string {
	return "trivy"
}

func (Parser) Supports(filename string) bool {
	return strings.EqualFold(filepath.Ext(filename), ".json") || strings.EqualFold(filepath.Ext(filename), ".sarif")
}

func (Parser) Parse(ctx context.Context, req ports.ParseRequest, sink ports.FindingSink) error {
	decoder := json.NewDecoder(req.Reader)

	token, err := decoder.Token()
	if err != nil {
		if err == io.EOF {
			return nil
		}
		return sferr.WrapJSON(sferr.CodeParseFailed, opParse, err, req.ReaderAt, "read trivy opening token")
	}
	delim, ok := token.(json.Delim)
	if !ok || delim != '{' {
		return sferr.New(sferr.CodeUnsupportedInput, opParse, "trivy report must be a JSON object")
	}

	doc := report{}
	sawResults := false
	supported := false

	for decoder.More() {
		if err := ctx.Err(); err != nil {
			return err
		}

		keyToken, err := decoder.Token()
		if err != nil {
			return sferr.WrapJSON(sferr.CodeParseFailed, opParse, err, req.ReaderAt, "decode trivy key")
		}
		key, ok := keyToken.(string)
		if !ok {
			return sferr.New(sferr.CodeParseFailed, opParse, "trivy key is not a string")
		}

		switch key {
		case "ArtifactName":
			if err := decoder.Decode(&doc.ArtifactName); err != nil {
				return sferr.WrapJSON(sferr.CodeParseFailed, opParse, err, req.ReaderAt, "decode artifact name")
			}
		case "ArtifactType":
			if err := decoder.Decode(&doc.ArtifactType); err != nil {
				return sferr.WrapJSON(sferr.CodeParseFailed, opParse, err, req.ReaderAt, "decode artifact type")
			}
		case "Metadata":
			if err := decoder.Decode(&doc.Metadata); err != nil {
				return sferr.WrapJSON(sferr.CodeParseFailed, opParse, err, req.ReaderAt, "decode metadata")
			}
		case "Results":
			sawResults = true
			ok, err := streamResults(ctx, decoder, req, sink, doc, &supported)
			if err != nil {
				return err
			}
			if !ok {
				return sferr.New(sferr.CodeParseFailed, opParse, "trivy results field must be an array")
			}
		default:
			var discard json.RawMessage
			if err := decoder.Decode(&discard); err != nil {
				return sferr.WrapJSON(sferr.CodeParseFailed, opParse, err, req.ReaderAt, "discard trivy field")
			}
		}
	}

	if _, err := decoder.Token(); err != nil {
		return sferr.WrapJSON(sferr.CodeParseFailed, opParse, err, req.ReaderAt, "read trivy closing token")
	}
	if !sawResults {
		return sferr.New(sferr.CodeUnsupportedInput, opParse, "trivy report results are missing")
	}
	if !supported {
		return sferr.New(sferr.CodeUnsupportedInput, opParse, "trivy report contains no supported finding types")
	}

	return nil
}

func (Parser) Hydrate(ctx context.Context, req ports.HydrateRequest) (evidence.Finding, error) {
	if err := ctx.Err(); err != nil {
		return evidence.Finding{}, err
	}
	if req.Meta.Range.Len() <= 0 {
		return evidence.Finding{}, sferr.New(sferr.CodeParseFailed, opHydrate, "trivy result range is empty")
	}

	section := io.NewSectionReader(req.Reader, req.Meta.Range.Start, req.Meta.Range.Len())
	rawResult, err := io.ReadAll(section)
	if err != nil {
		return evidence.Finding{}, sferr.Wrap(sferr.CodeIO, opHydrate, err, "read trivy result section")
	}

	var parsedResult result
	if err := json.Unmarshal(trimHydratedJSON(rawResult), &parsedResult); err != nil {
		return evidence.Finding{}, sferr.Wrap(sferr.CodeParseFailed, opHydrate, err, "decode trivy result section")
	}

	var header reportContext
	if err := json.Unmarshal(req.Meta.Context, &header); err != nil {
		return evidence.Finding{}, sferr.Wrap(sferr.CodeParseFailed, opHydrate, err, "decode trivy report context")
	}

	doc := report{
		ArtifactName: header.ArtifactName,
		ArtifactType: header.ArtifactType,
		Metadata:     header.Metadata,
	}

	switch req.Meta.Hint {
	case hydrateVulnerability:
		if req.Meta.Index < 0 || req.Meta.Index >= len(parsedResult.Vulnerabilities) {
			return evidence.Finding{}, io.EOF
		}
		return mapVulnerability(reqToParse(req), doc, parsedResult, parsedResult.Vulnerabilities[req.Meta.Index]), nil
	case hydrateSecret:
		if req.Meta.Index < 0 || req.Meta.Index >= len(parsedResult.Secrets) {
			return evidence.Finding{}, io.EOF
		}
		return mapSecret(reqToParse(req), doc, parsedResult, parsedResult.Secrets[req.Meta.Index]), nil
	default:
		return evidence.Finding{}, sferr.New(sferr.CodeParseFailed, opHydrate, "unsupported trivy hydration target")
	}
}

func reqToParse(req ports.HydrateRequest) ports.ParseRequest {
	return ports.ParseRequest{
		Source:   req.Source,
		Filename: req.Filename,
	}
}

func trimHydratedJSON(raw []byte) []byte {
	trimmed := bytes.TrimLeft(raw, " \t\r\n,")
	return bytes.TrimSpace(trimmed)
}

func streamResults(
	ctx context.Context,
	decoder *json.Decoder,
	req ports.ParseRequest,
	sink ports.FindingSink,
	doc report,
	supported *bool,
) (bool, error) {
	token, err := decoder.Token()
	if err != nil {
		return false, sferr.WrapJSON(sferr.CodeParseFailed, opParse, err, req.ReaderAt, "read trivy results token")
	}
	delim, ok := token.(json.Delim)
	if !ok || delim != '[' {
		return false, nil
	}

	contextPayload, err := json.Marshal(reportContext{
		ArtifactName: doc.ArtifactName,
		ArtifactType: doc.ArtifactType,
		Metadata:     doc.Metadata,
	})
	if err != nil {
		return true, sferr.Wrap(sferr.CodeParseFailed, opParse, err, "encode trivy report context")
	}

	for decoder.More() {
		if err := ctx.Err(); err != nil {
			return true, err
		}

		start := decoder.InputOffset()
		var rawResult json.RawMessage
		if err := decoder.Decode(&rawResult); err != nil {
			return true, sferr.WrapJSON(sferr.CodeParseFailed, opParse, err, req.ReaderAt, "decode trivy result")
		}

		var parsed result
		if err := json.Unmarshal(rawResult, &parsed); err != nil {
			return true, sferr.WrapJSON(sferr.CodeParseFailed, opParse, err, req.ReaderAt, "decode trivy result payload")
		}

		meta := ports.ParseMetadata{
			Range: evidence.ByteOffsetRange{
				Start: start,
				End:   decoder.InputOffset(),
			},
			Context: contextPayload,
		}

		for index, item := range parsed.Vulnerabilities {
			*supported = true
			itemMeta := meta
			itemMeta.Hint = hydrateVulnerability
			itemMeta.Index = index
			if err := sink.WriteFinding(ctx, mapVulnerability(req, doc, parsed, item), itemMeta); err != nil {
				return true, err
			}
		}

		for index, item := range parsed.Secrets {
			*supported = true
			itemMeta := meta
			itemMeta.Hint = hydrateSecret
			itemMeta.Index = index
			if err := sink.WriteFinding(ctx, mapSecret(req, doc, parsed, item), itemMeta); err != nil {
				return true, err
			}
		}
	}

	if _, err := decoder.Token(); err != nil {
		return true, sferr.WrapJSON(sferr.CodeParseFailed, opParse, err, req.ReaderAt, "read trivy results closing token")
	}

	return true, nil
}

func mapVulnerability(req ports.ParseRequest, doc report, result result, item vulnerability) evidence.Finding {
	score, vector := bestCVSS(item.CVSS)
	refs := make([]evidence.Reference, 0, len(item.References)+1)
	if item.PrimaryURL != "" {
		refs = append(refs, evidence.Reference{Type: "advisory", URL: item.PrimaryURL})
	}
	for _, reference := range item.References {
		if strings.TrimSpace(reference) == "" {
			continue
		}
		refs = append(refs, evidence.Reference{Type: "reference", URL: reference})
	}

	return evidence.Finding{
		SchemaVersion: evidence.SchemaVersion,
		Kind:          evidence.KindSCA,
		Title:         firstNonEmpty(item.Title, item.VulnerabilityID, "trivy vulnerability"),
		Description:   item.Description,
		Severity: evidence.Severity{
			Label:  toSeverityLabel(item.Severity),
			Score:  score,
			Vector: vector,
		},
		Rule: evidence.Rule{
			ID:       item.VulnerabilityID,
			Name:     firstNonEmpty(item.Title, item.VulnerabilityID),
			Category: "vulnerability",
		},
		Artifact: evidence.Artifact{
			Type: doc.ArtifactType,
			Name: firstNonEmpty(doc.ArtifactName, result.Target),
		},
		Package: &evidence.Package{
			Type:         result.Type,
			Name:         item.PkgName,
			Version:      item.InstalledVersion,
			FixedVersion: item.FixedVersion,
			PackageURL:   item.PkgIdentifier.PURL,
		},
		Vulnerability: &evidence.Vulnerability{
			ID:         item.VulnerabilityID,
			CWE:        append([]string(nil), item.CweIDs...),
			CVSSScore:  score,
			CVSSVector: vector,
		},
		Image:      mapImage(doc),
		References: refs,
		Source: evidence.SourceRecord{
			Provider:       req.Source.Provider,
			Scanner:        firstNonEmpty(req.Source.ToolName, "trivy"),
			ScannerVersion: req.Source.ToolVersion,
			FindingID:      item.VulnerabilityID,
		},
	}
}

func mapSecret(req ports.ParseRequest, doc report, result result, item secret) evidence.Finding {
	return evidence.Finding{
		SchemaVersion: evidence.SchemaVersion,
		Kind:          evidence.KindSecrets,
		Title:         firstNonEmpty(item.Title, item.RuleID, "trivy secret"),
		Description:   firstNonEmpty(item.Category, "secret finding"),
		Severity: evidence.Severity{
			Label: toSeverityLabel(item.Severity),
		},
		Rule: evidence.Rule{
			ID:       item.RuleID,
			Name:     firstNonEmpty(item.Title, item.RuleID),
			Category: "secret",
		},
		PrimaryLocation: evidence.Location{
			URI:     result.Target,
			Line:    item.StartLine,
			EndLine: item.EndLine,
		},
		Artifact: evidence.Artifact{
			Type: "file",
			Name: result.Target,
		},
		Secret: &evidence.Secret{
			Type:        firstNonEmpty(item.Category, "secret"),
			Provider:    "trivy",
			Fingerprint: firstNonEmpty(item.Fingerprint, item.RuleID+"|"+result.Target+"|"+item.Match),
			Redacted:    redactSecret(item.Match),
		},
		Image: mapImage(doc),
		Source: evidence.SourceRecord{
			Provider:       req.Source.Provider,
			Scanner:        firstNonEmpty(req.Source.ToolName, "trivy"),
			ScannerVersion: req.Source.ToolVersion,
			FindingID:      item.RuleID,
		},
	}
}

func bestCVSS(values cvssMap) (float64, string) {
	for _, candidate := range values {
		if candidate.V3Score > 0 {
			return candidate.V3Score, candidate.V3Vector
		}
	}

	return 0, ""
}

func mapImage(doc report) *evidence.Image {
	if strings.TrimSpace(doc.Metadata.ImageID) == "" && strings.TrimSpace(doc.ArtifactName) == "" {
		return nil
	}

	return &evidence.Image{
		Repository: doc.ArtifactName,
		Digest:     doc.Metadata.ImageID,
		BaseDigest: doc.Metadata.DiffID,
	}
}

func toSeverityLabel(value string) evidence.SeverityLabel {
	switch strings.ToLower(strings.TrimSpace(value)) {
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

func redactSecret(value string) string {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return ""
	}
	if len(trimmed) <= 6 {
		return "***"
	}

	return trimmed[:3] + "***" + trimmed[len(trimmed)-3:]
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}

	return ""
}
