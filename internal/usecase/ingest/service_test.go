package ingest

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"strconv"
	"sync"
	"testing"

	"github.com/secfacts/secfacts/internal/domain/correlation"
	"github.com/secfacts/secfacts/internal/domain/dedup"
	"github.com/secfacts/secfacts/internal/domain/evidence"
	"github.com/secfacts/secfacts/internal/ports"
	"github.com/secfacts/secfacts/internal/usecase/normalize"
)

func BenchmarkServiceRun(b *testing.B) {
	for _, size := range []int{1000, 10000, 100000} {
		b.Run(strconv.Itoa(size), func(b *testing.B) {
			benchmarkServiceRun(b, size)
		})
	}
}

func BenchmarkServiceRunStable100000(b *testing.B) {
	benchmarkServiceRun(b, 100000)
}

func benchmarkServiceRun(b *testing.B, size int) {
	b.Helper()

	dataset := benchmarkDataset(size)
	service := benchmarkServiceWithParser(benchmarkParser{
		dataset: dataset,
	})

	// Keep the timed region focused on the pipeline itself rather than heap carry-over.
	runtime.GC()
	debug.FreeOSMemory()

	b.ReportAllocs()
	b.SetBytes(int64(len(dataset)))
	b.ResetTimer()

	path := benchmarkInputPath(b)
	for i := 0; i < b.N; i++ {
		_, err := service.Run(context.Background(), Request{
			Inputs: []Input{{
				Path: path,
				Source: evidence.SourceDescriptor{
					Provider:    "benchmark",
					ToolName:    "benchmark",
					ToolVersion: "1.0.0",
				},
			}},
			Output: ports.ExportRequest{
				Writer: io.Discard,
			},
		})
		if err != nil {
			b.Fatalf("Run returned error: %v", err)
		}
	}
}

func benchmarkServiceWithParser(parser ports.Parser) Service {
	identityBuilder := evidence.DefaultIdentityBuilder{}
	interner := evidence.NewInterner()

	return Service{
		Parsers: []ports.Parser{parser},
		Normalizer: normalize.Service{
			IdentityBuilder: identityBuilder,
			Interner:        interner,
		},
		Deduplicator: dedup.Service{Builder: identityBuilder},
		Correlator:   correlation.Service{},
		Config: Config{
			DiscoveryWorkers: 1,
			ParseWorkers:     4,
			NormalizeWorkers: 4,
			DiscoveryBuffer:  64,
			FindingBuffer:    1024,
		},
	}
}

type benchmarkParser struct {
	dataset []byte
}

func (benchmarkParser) Provider() string {
	return "benchmark"
}

func (benchmarkParser) Supports(filename string) bool {
	return filename != ""
}

func (p benchmarkParser) Parse(ctx context.Context, req ports.ParseRequest, sink ports.FindingSink) error {
	decoder := json.NewDecoder(bytes.NewReader(p.dataset))

	token, err := decoder.Token()
	if err != nil {
		return err
	}

	delim, ok := token.(json.Delim)
	if !ok || delim != '[' {
		return io.ErrUnexpectedEOF
	}

	for index := 0; decoder.More(); index++ {
		if err := ctx.Err(); err != nil {
			return err
		}

		var finding evidence.Finding
		if err := decoder.Decode(&finding); err != nil {
			return err
		}

		finding.SchemaVersion = evidence.SchemaVersion
		finding.Source.Provider = req.Source.Provider
		finding.Source.Scanner = req.Source.ToolName
		finding.Source.ScannerVersion = req.Source.ToolVersion

		if err := sink.WriteFinding(ctx, finding, ports.ParseMetadata{Index: index}); err != nil {
			return err
		}
	}

	_, err = decoder.Token()
	return err
}

func (p benchmarkParser) Hydrate(ctx context.Context, req ports.HydrateRequest) (evidence.Finding, error) {
	decoder := json.NewDecoder(bytes.NewReader(p.dataset))

	token, err := decoder.Token()
	if err != nil {
		return evidence.Finding{}, err
	}

	delim, ok := token.(json.Delim)
	if !ok || delim != '[' {
		return evidence.Finding{}, io.ErrUnexpectedEOF
	}

	for i := 0; decoder.More(); i++ {
		if err := ctx.Err(); err != nil {
			return evidence.Finding{}, err
		}

		var finding evidence.Finding
		if err := decoder.Decode(&finding); err != nil {
			return evidence.Finding{}, err
		}
		if i != req.Meta.Index {
			continue
		}

		finding.SchemaVersion = evidence.SchemaVersion
		finding.Source.Provider = req.Source.Provider
		finding.Source.Scanner = req.Source.ToolName
		finding.Source.ScannerVersion = req.Source.ToolVersion
		return finding, nil
	}

	return evidence.Finding{}, io.EOF
}

var (
	benchmarkDatasetOnce sync.Map
	benchmarkDatasetMu   sync.Mutex
)

func benchmarkDataset(size int) []byte {
	if dataset, ok := benchmarkDatasetOnce.Load(size); ok {
		return dataset.([]byte)
	}

	benchmarkDatasetMu.Lock()
	defer benchmarkDatasetMu.Unlock()

	if dataset, ok := benchmarkDatasetOnce.Load(size); ok {
		return dataset.([]byte)
	}

	findings := make([]evidence.Finding, 0, size)
	for i := 0; i < size; i++ {
		findings = append(findings, evidence.Finding{
			Kind:  evidence.KindSCA,
			Title: "benchmark finding " + strconv.Itoa(i),
			Severity: evidence.Severity{
				Label: evidence.SeverityHigh,
				Score: 7.5,
			},
			Rule: evidence.Rule{
				ID: "CVE-2024-" + strconv.Itoa(i),
			},
			Package: &evidence.Package{
				Name:       "pkg-" + strconv.Itoa(i),
				Version:    "1.0.0",
				PackageURL: "pkg:generic/pkg-" + strconv.Itoa(i) + "@1.0.0",
			},
			Vulnerability: &evidence.Vulnerability{
				ID:        "CVE-2024-" + strconv.Itoa(i),
				CVSSScore: 7.5,
			},
		})
	}

	dataset, err := json.Marshal(findings)
	if err != nil {
		panic(err)
	}

	benchmarkDatasetOnce.Store(size, dataset)
	return dataset
}

func benchmarkInputPath(tb testing.TB) string {
	tb.Helper()

	_, file, _, ok := runtime.Caller(0)
	if !ok {
		tb.Fatal("runtime.Caller returned no file information")
	}

	return filepath.Clean(file)
}
