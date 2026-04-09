package iemjson

import (
	"bytes"
	"context"
	"testing"

	"github.com/axon/axon/internal/domain/evidence"
	"github.com/axon/axon/internal/ports"
)

func FuzzParser(f *testing.F) {
	parser := Parser{}

	// Seed corpus
	f.Add([]byte(`[{"Kind":"sca","Vulnerability":{"ID":"CVE-1"}}]`))
	f.Add([]byte(`{"findings":[{"Kind":"sast","Title":"T1"}]}`))
	f.Add([]byte(`{"Kind":"cloud"}\n{"Kind":"secrets"}`)) // NDJSON

	f.Fuzz(func(t *testing.T, data []byte) {
		sink := sinkWithMetaFunc(func(_ context.Context, _ evidence.Finding, _ ports.ParseMetadata) error {
			return nil
		})

		// Test JSON
		_ = parser.Parse(context.Background(), ports.ParseRequest{
			Filename: "fuzz.json",
			Reader:   bytes.NewReader(data),
		}, sink)

		// Test NDJSON
		_ = parser.Parse(context.Background(), ports.ParseRequest{
			Filename: "fuzz.jsonl",
			Reader:   bytes.NewReader(data),
		}, sink)
	})
}

func FuzzHydrate(f *testing.F) {
	parser := Parser{}

	f.Add([]byte(`{"Kind":"sca","Title":"T1"}`), int64(0), int64(26))

	f.Fuzz(func(t *testing.T, data []byte, start int64, length int64) {
		if length < 0 || length > 1024*1024 { // Cap at 1MB for fuzzing
			return
		}
		if start < 0 || start+length > int64(len(data)) {
			return
		}

		_, _ = parser.Hydrate(context.Background(), ports.HydrateRequest{
			Reader: bytes.NewReader(data),
			Meta: ports.ParseMetadata{
				Range: evidence.ByteOffsetRange{
					Start: start,
					End:   start + length,
				},
			},
		})
	})
}
