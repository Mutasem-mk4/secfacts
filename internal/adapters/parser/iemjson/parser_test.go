package iemjson

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"github.com/axon/axon/internal/domain/evidence"
	"github.com/axon/axon/internal/ports"
)

func TestParserParsesFindingArray(t *testing.T) {
	t.Parallel()

	parser := Parser{}
	var findings []evidence.Finding

	err := parser.Parse(context.Background(), ports.ParseRequest{
		Filename: "sample.json",
		Reader: strings.NewReader(`[
			{
				"Kind":"sca",
				"Severity":{"Label":"high"},
				"Package":{"Name":"openssl","PackageURL":"pkg:apk/alpine/openssl@1.0.2"},
				"Vulnerability":{"ID":"CVE-2024-0001","CVSSScore":8.2}
			}
		]`),
	}, sinkFunc(func(_ context.Context, finding evidence.Finding) error {
		findings = append(findings, finding)
		return nil
	}))
	if err != nil {
		t.Fatalf("Parse returned error: %v", err)
	}

	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].Vulnerability == nil || findings[0].Vulnerability.CVSSScore != 8.2 {
		t.Fatalf("expected vulnerability CVSS score 8.2, got %#v", findings[0].Vulnerability)
	}
}

func TestParserHydratesFindingArrayRange(t *testing.T) {
	t.Parallel()

	input := `[
		{"Kind":"sca","Title":"first","Severity":{"Label":"high"},"Rule":{"ID":"CVE-2024-0001"}},
		{"Kind":"sca","Title":"second","Severity":{"Label":"medium"},"Rule":{"ID":"CVE-2024-0002"}}
	]`

	parser := Parser{}
	type record struct {
		finding evidence.Finding
		meta    ports.ParseMetadata
	}
	records := make([]record, 0, 2)

	err := parser.Parse(context.Background(), ports.ParseRequest{
		Filename: "sample.json",
		Reader:   strings.NewReader(input),
		Source: evidence.SourceDescriptor{
			Provider:    "iemjson",
			ToolName:    "axon",
			ToolVersion: "1.0.0",
		},
	}, sinkWithMetaFunc(func(_ context.Context, finding evidence.Finding, meta ports.ParseMetadata) error {
		records = append(records, record{finding: finding, meta: meta})
		return nil
	}))
	if err != nil {
		t.Fatalf("Parse returned error: %v", err)
	}

	for _, item := range records {
		hydrated, err := parser.Hydrate(context.Background(), ports.HydrateRequest{
			Filename: "sample.json",
			Reader:   bytes.NewReader([]byte(input)),
			Source: evidence.SourceDescriptor{
				Provider:    "iemjson",
				ToolName:    "axon",
				ToolVersion: "1.0.0",
			},
			Meta: item.meta,
		})
		if err != nil {
			t.Fatalf("Hydrate returned error: %v", err)
		}
		if hydrated.Title != item.finding.Title {
			t.Fatalf("expected title %q, got %q", item.finding.Title, hydrated.Title)
		}
	}
}

type sinkFunc func(context.Context, evidence.Finding) error

func (f sinkFunc) WriteFinding(ctx context.Context, finding evidence.Finding, _ ports.ParseMetadata) error {
	return f(ctx, finding)
}

type sinkWithMetaFunc func(context.Context, evidence.Finding, ports.ParseMetadata) error

func (f sinkWithMetaFunc) WriteFinding(ctx context.Context, finding evidence.Finding, meta ports.ParseMetadata) error {
	return f(ctx, finding, meta)
}
