package sarif

import (
	"bufio"
	"context"
	"encoding/json"
	"io"

	sferr "github.com/axon/axon/internal/domain/errors"
	"github.com/axon/axon/internal/domain/evidence"
	"github.com/axon/axon/internal/ports"
)

const (
	format    = "sarif"
	version   = "2.1.0"
	schemaURI = "https://json.schemastore.org/sarif-2.1.0.json"
	opExport  = "sarif.Exporter.Export"
)

type Exporter struct{}

func (Exporter) Format() string {
	return format
}

func (Exporter) Export(ctx context.Context, req ports.ExportRequest) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if req.Writer == nil {
		return sferr.New(sferr.CodeInvalidArgument, opExport, "writer is required")
	}

	report := fromDocument(req.Document)
	iterator := req.Findings
	if iterator == nil {
		iterator = ports.NewSliceFindingIterator(req.Document.Findings)
	}
	defer iterator.Close()

	writer := bufio.NewWriter(req.Writer)
	defer writer.Flush()

	if _, err := writer.WriteString(`{"version":"` + version + `","$schema":"` + schemaURI + `","runs":[{"results":[`); err != nil {
		return sferr.Wrap(sferr.CodeExportFailed, opExport, err, "start SARIF report")
	}

	rules := make(map[string]reportingDescriptor)
	first := true
	for {
		finding, err := iterator.Next(ctx)
		if err == io.EOF {
			break
		}
		if err != nil {
			return sferr.Wrap(sferr.CodeExportFailed, opExport, err, "iterate findings")
		}
		if finding.Rule.ID != "" {
			rules[finding.Rule.ID] = reportingDescriptor{
				ID:   finding.Rule.ID,
				Name: finding.Rule.Name,
				ShortDescription: message{
					Text: finding.Title,
				},
			}
		}

		payload, err := json.Marshal(result{
			RuleID:    finding.Rule.ID,
			Level:     sarifLevel(finding.Severity),
			Message:   message{Text: finding.Title},
			Locations: buildLocations(finding),
			PartialFingerprints: map[string]string{
				"dedupKey":       finding.Identity.DedupKey.String(),
				"fingerprintV1":  finding.Identity.FingerprintV1.String(),
				"naturalKeyHash": finding.Identity.NaturalKey.String(),
			},
			Properties: map[string]any{
				"kind":           finding.Kind,
				"severity_score": finding.Severity.Score,
				"provider":       finding.Source.Provider,
			},
		})
		if err != nil {
			return sferr.Wrap(sferr.CodeExportFailed, opExport, err, "marshal SARIF result")
		}
		if !first {
			if _, err := writer.WriteString(","); err != nil {
				return sferr.Wrap(sferr.CodeExportFailed, opExport, err, "write SARIF delimiter")
			}
		}
		first = false
		if _, err := writer.Write(payload); err != nil {
			return sferr.Wrap(sferr.CodeExportFailed, opExport, err, "write SARIF result")
		}
	}

	descriptors := make([]reportingDescriptor, 0, len(rules))
	for _, descriptor := range rules {
		descriptors = append(descriptors, descriptor)
	}
	driverPayload, err := json.Marshal(driver{
		Name:    report.Runs[0].Tool.Driver.Name,
		Version: report.Runs[0].Tool.Driver.Version,
		Rules:   descriptors,
	})
	if err != nil {
		return sferr.Wrap(sferr.CodeExportFailed, opExport, err, "marshal SARIF driver")
	}
	if _, err := writer.WriteString(`],"tool":{"driver":`); err != nil {
		return sferr.Wrap(sferr.CodeExportFailed, opExport, err, "write SARIF tool key")
	}
	if _, err := writer.Write(driverPayload); err != nil {
		return sferr.Wrap(sferr.CodeExportFailed, opExport, err, "write SARIF driver")
	}
	if _, err := writer.WriteString(`}}]}` + "\n"); err != nil {
		return sferr.Wrap(sferr.CodeExportFailed, opExport, err, "finalize SARIF report")
	}

	return nil
}

type report struct {
	Version string `json:"version"`
	Schema  string `json:"$schema"`
	Runs    []run  `json:"runs"`
}

type run struct {
	Tool    tool     `json:"tool"`
	Results []result `json:"results"`
}

type tool struct {
	Driver driver `json:"driver"`
}

type driver struct {
	Name           string                `json:"name"`
	Version        string                `json:"version,omitempty"`
	InformationURI string                `json:"informationUri,omitempty"`
	Rules          []reportingDescriptor `json:"rules,omitempty"`
}

type reportingDescriptor struct {
	ID               string  `json:"id"`
	Name             string  `json:"name,omitempty"`
	ShortDescription message `json:"shortDescription,omitempty"`
}

type result struct {
	RuleID              string            `json:"ruleId,omitempty"`
	Level               string            `json:"level"`
	Message             message           `json:"message"`
	Locations           []location        `json:"locations,omitempty"`
	PartialFingerprints map[string]string `json:"partialFingerprints,omitempty"`
	Properties          map[string]any    `json:"properties,omitempty"`
}

type message struct {
	Text string `json:"text"`
}

type location struct {
	PhysicalLocation physicalLocation `json:"physicalLocation"`
}

type physicalLocation struct {
	ArtifactLocation artifactLocation `json:"artifactLocation"`
	Region           region           `json:"region,omitempty"`
}

type artifactLocation struct {
	URI string `json:"uri"`
}

type region struct {
	StartLine   int `json:"startLine,omitempty"`
	StartColumn int `json:"startColumn,omitempty"`
	EndLine     int `json:"endLine,omitempty"`
	EndColumn   int `json:"endColumn,omitempty"`
}

func fromDocument(document evidence.Document) report {
	rules := make(map[string]reportingDescriptor)
	results := make([]result, 0, len(document.Findings))

	for _, finding := range document.Findings {
		if finding.Rule.ID != "" {
			rules[finding.Rule.ID] = reportingDescriptor{
				ID:   finding.Rule.ID,
				Name: finding.Rule.Name,
				ShortDescription: message{
					Text: finding.Title,
				},
			}
		}

		results = append(results, result{
			RuleID:    finding.Rule.ID,
			Level:     sarifLevel(finding.Severity),
			Message:   message{Text: finding.Title},
			Locations: buildLocations(finding),
			PartialFingerprints: map[string]string{
				"dedupKey":       finding.Identity.DedupKey.String(),
				"fingerprintV1":  finding.Identity.FingerprintV1.String(),
				"naturalKeyHash": finding.Identity.NaturalKey.String(),
			},
			Properties: map[string]any{
				"kind":           finding.Kind,
				"severity_score": finding.Severity.Score,
				"provider":       finding.Source.Provider,
			},
		})
	}

	descriptors := make([]reportingDescriptor, 0, len(rules))
	for _, descriptor := range rules {
		descriptors = append(descriptors, descriptor)
	}

	return report{
		Version: version,
		Schema:  schemaURI,
		Runs: []run{{
			Tool: tool{
				Driver: driver{
					Name:    document.Source.ToolName,
					Version: document.Source.ToolVersion,
					Rules:   descriptors,
				},
			},
			Results: results,
		}},
	}
}

func sarifLevel(severity evidence.Severity) string {
	switch {
	case severity.Score >= 7:
		return "error"
	case severity.Score >= 4:
		return "warning"
	default:
		return "note"
	}
}

func buildLocations(finding evidence.Finding) []location {
	if finding.PrimaryLocation.URI == "" {
		return nil
	}

	return []location{{
		PhysicalLocation: physicalLocation{
			ArtifactLocation: artifactLocation{
				URI: finding.PrimaryLocation.URI,
			},
			Region: region{
				StartLine:   finding.PrimaryLocation.Line,
				StartColumn: finding.PrimaryLocation.Column,
				EndLine:     finding.PrimaryLocation.EndLine,
				EndColumn:   finding.PrimaryLocation.EndColumn,
			},
		},
	}}
}
