package ingest

import (
	"context"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/sync/errgroup"

	"github.com/secfacts/secfacts/internal/domain/correlation"
	sferr "github.com/secfacts/secfacts/internal/domain/errors"
	"github.com/secfacts/secfacts/internal/domain/evidence"
	"github.com/secfacts/secfacts/internal/ports"
)

const opRun = "ingest.Service.Run"

type Service struct {
	Parsers      []ports.Parser
	Normalizer   ports.Normalizer
	Deduplicator ports.Deduplicator
	Correlator   ports.Correlator
	Exporter     ports.Exporter
	Observer     ports.Observer
	Config       Config
}

type Config struct {
	DiscoveryWorkers int
	ParseWorkers     int
	NormalizeWorkers int
	DiscoveryBuffer  int
	FindingBuffer    int
}

type Request struct {
	Inputs         []Input
	Output         ports.ExportRequest
	RetainFindings bool
}

type Result struct {
	Document evidence.Document
	Findings []evidence.Finding
	Counts   map[evidence.SeverityLabel]map[evidence.Kind]int
}

type Input struct {
	Path   string
	Source evidence.SourceDescriptor
	Reader io.ReadCloser
}

type discoveredFile struct {
	path   string
	source evidence.SourceDescriptor
	open   func() (io.ReadCloser, error)
}

type findingEnvelope struct {
	finding evidence.Finding
	ref     evidence.FindingRef
}

type compactCorrelator interface {
	CorrelateCompact(ctx context.Context, compact []correlation.CompactFinding, representatives map[string]evidence.Finding) ([]evidence.RootCauseCluster, error)
}

var envelopePool = sync.Pool{
	New: func() any {
		return &findingEnvelope{}
	},
}

func (s Service) Run(ctx context.Context, req Request) (Result, error) {
	if err := s.validate(); err != nil {
		return Result{}, err
	}

	cfg := s.withDefaults()
	group, groupCtx := errgroup.WithContext(ctx)

	discoveredCh := make(chan discoveredFile, cfg.DiscoveryBuffer)
	parsedCh := make(chan *findingEnvelope, cfg.FindingBuffer)
	normalizedCh := make(chan *findingEnvelope, cfg.FindingBuffer)
	uniqueCh := make(chan *findingEnvelope, cfg.FindingBuffer)

	var discoveredFiles atomic.Int64
	var parsedFindings atomic.Int64
	var totalFindings atomic.Int64
	var parseWG sync.WaitGroup
	var normalizeWG sync.WaitGroup

	group.Go(func() error {
		defer close(discoveredCh)
		return s.runDiscovery(groupCtx, req.Inputs, discoveredCh, cfg.DiscoveryWorkers, &discoveredFiles)
	})

	for i := 0; i < cfg.ParseWorkers; i++ {
		parseWG.Add(1)
		group.Go(func() error {
			defer parseWG.Done()
			return s.runParse(groupCtx, discoveredCh, parsedCh, &parsedFindings)
		})
	}

	group.Go(func() error {
		parseWG.Wait()
		close(parsedCh)
		return nil
	})

	for i := 0; i < cfg.NormalizeWorkers; i++ {
		normalizeWG.Add(1)
		group.Go(func() error {
			defer normalizeWG.Done()
			return s.runNormalize(groupCtx, parsedCh, normalizedCh)
		})
	}

	group.Go(func() error {
		normalizeWG.Wait()
		close(normalizedCh)
		return nil
	})

	group.Go(func() error {
		defer close(uniqueCh)
		return s.runDeduplicate(groupCtx, normalizedCh, uniqueCh, &totalFindings)
	})

	estimatedFindings := cfg.FindingBuffer
	if estimatedFindings < len(req.Inputs) {
		estimatedFindings = len(req.Inputs)
	}

	var (
		findings        []evidence.Finding
		compactFindings = make([]correlation.CompactFinding, 0, estimatedFindings)
		representatives = make(map[string]evidence.Finding, estimatedFindings/4+1)
		selectedRefs    = make(map[string][]evidence.FindingRef, estimatedFindings/2+1)
		counts          = newCountMatrix()
	)
	if req.RetainFindings {
		findings = make([]evidence.Finding, 0, estimatedFindings)
	}

	group.Go(func() error {
		for {
			select {
			case <-groupCtx.Done():
				return groupCtx.Err()
			case envelope, ok := <-uniqueCh:
				if !ok {
					return nil
				}

				finding := envelope.finding
				ref := envelope.ref
				compact := correlation.Compact(finding, ref)
				compactFindings = append(compactFindings, compact)
				incrementCount(counts, compact.SeverityLabel, compact.Kind)
				markSelected(selectedRefs, ref)
				updateRepresentative(representatives, compact, finding)
				if req.RetainFindings {
					findings = append(findings, finding)
				}

				releaseEnvelope(envelope)
			}
		}
	})

	if err := group.Wait(); err != nil {
		return Result{}, err
	}

	if s.Observer != nil {
		s.Observer.OnFilesDiscovered(ctx, int(discoveredFiles.Load()))
		s.Observer.OnFindingsParsed(ctx, int(parsedFindings.Load()))
		s.Observer.OnFindingsDeduplicated(ctx, int(totalFindings.Load()), len(compactFindings))
	}

	correlations, err := s.correlate(ctx, compactFindings, representatives)
	if err != nil {
		return Result{}, sferr.Wrap(sferr.CodeCorrelateFailed, opRun, err, "correlate findings")
	}

	document := evidence.Document{
		SchemaVersion: evidence.SchemaVersion,
		GeneratedAt:   time.Now().UTC(),
		Source:        primarySource(req.Inputs),
		Summary: evidence.Summary{
			TotalFindings:      int(totalFindings.Load()),
			UniqueFindings:     len(compactFindings),
			CorrelatedFindings: countCorrelated(correlations),
		},
		Correlations: correlations,
	}
	if req.RetainFindings {
		document.Findings = findings
	}

	if s.Exporter != nil && req.Output.Writer != nil {
		req.Output.Document = document
		if req.RetainFindings {
			req.Output.Findings = ports.NewSliceFindingIterator(findings)
		} else {
			req.Output.Findings = newRehydratingIterator(ctx, s, req.Inputs, selectedRefs)
		}
		if err := s.Exporter.Export(ctx, req.Output); err != nil {
			if s.Observer != nil && (errors.Is(err, context.Canceled) || errors.Is(ctx.Err(), context.Canceled)) {
				s.Observer.OnPartialExport(ctx, s.Exporter.Format(), len(compactFindings), "export interrupted during hydration; output may be incomplete")
			}
			return Result{}, sferr.Wrap(sferr.CodeExportFailed, opRun, err, "export findings")
		}
		if s.Observer != nil {
			s.Observer.OnExportCompleted(ctx, s.Exporter.Format(), len(compactFindings))
		}
	}

	return Result{
		Document: document,
		Findings: findings,
		Counts:   counts,
	}, nil
}

func (s Service) validate() error {
	switch {
	case len(s.Parsers) == 0:
		return sferr.New(sferr.CodeInvalidConfig, opRun, "at least one parser is required")
	case s.Normalizer == nil:
		return sferr.New(sferr.CodeInvalidConfig, opRun, "normalizer is required")
	case s.Deduplicator == nil:
		return sferr.New(sferr.CodeInvalidConfig, opRun, "deduplicator is required")
	case s.Correlator == nil:
		return sferr.New(sferr.CodeInvalidConfig, opRun, "correlator is required")
	default:
		return nil
	}
}

func (s Service) withDefaults() Config {
	cfg := s.Config
	if cfg.DiscoveryWorkers <= 0 {
		cfg.DiscoveryWorkers = 1
	}
	if cfg.ParseWorkers <= 0 {
		cfg.ParseWorkers = 2
	}
	if cfg.NormalizeWorkers <= 0 {
		cfg.NormalizeWorkers = 4
	}
	if cfg.DiscoveryBuffer <= 0 {
		cfg.DiscoveryBuffer = 64
	}
	if cfg.FindingBuffer <= 0 {
		cfg.FindingBuffer = 512
	}

	return cfg
}

func (s Service) runDiscovery(ctx context.Context, inputs []Input, out chan<- discoveredFile, workers int, discoveredFiles *atomic.Int64) error {
	jobs := make(chan Input, len(inputs))
	for _, input := range inputs {
		jobs <- input
	}
	close(jobs)

	group, groupCtx := errgroup.WithContext(ctx)
	for i := 0; i < workers; i++ {
		group.Go(func() error {
			for {
				select {
				case <-groupCtx.Done():
					return groupCtx.Err()
				case input, ok := <-jobs:
					if !ok {
						return nil
					}
					if err := discoverInput(groupCtx, input, out, discoveredFiles); err != nil {
						return err
					}
				}
			}
		})
	}

	return group.Wait()
}

func (s Service) runParse(ctx context.Context, in <-chan discoveredFile, out chan<- *findingEnvelope, parsedFindings *atomic.Int64) error {
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case file, ok := <-in:
			if !ok {
				return nil
			}
			if err := s.parseFile(ctx, file, out, parsedFindings); err != nil {
				return err
			}
		}
	}
}

func (s Service) parseFile(ctx context.Context, file discoveredFile, out chan<- *findingEnvelope, parsedFindings *atomic.Int64) error {
	parsers := selectParsers(s.Parsers, file.path)
	if len(parsers) == 0 {
		return sferr.New(sferr.CodeUnsupportedInput, opRun, "no parser supports input: "+file.path)
	}

	var lastErr error
	for _, parser := range parsers {
		handle, err := file.open()
		if err != nil {
			return sferr.Wrap(sferr.CodeIO, opRun, err, "open input")
		}

		sink := parserSinkFunc(func(ctx context.Context, finding evidence.Finding, meta ports.ParseMetadata) error {
			envelope := envelopePool.Get().(*findingEnvelope)
			envelope.finding = finding
			envelope.ref = findingRefForParse(file.path, meta)
			parsedFindings.Add(1)

			select {
			case <-ctx.Done():
				releaseEnvelope(envelope)
				return ctx.Err()
			case out <- envelope:
				return nil
			}
		})

		err = parser.Parse(ctx, ports.ParseRequest{
			Source:   file.source,
			Filename: file.path,
			Reader:   handle,
		}, sink)
		_ = handle.Close()
		if err == nil {
			return nil
		}
		if sferr.IsCode(err, sferr.CodeUnsupportedInput) {
			lastErr = err
			continue
		}

		return sferr.Wrap(sferr.CodeParseFailed, opRun, err, "parse input")
	}

	if lastErr != nil {
		return sferr.Wrap(sferr.CodeParseFailed, opRun, lastErr, "parse input")
	}

	return sferr.New(sferr.CodeUnsupportedInput, opRun, "no parser supports input: "+file.path)
}

func (s Service) runNormalize(ctx context.Context, in <-chan *findingEnvelope, out chan<- *findingEnvelope) error {
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case envelope, ok := <-in:
			if !ok {
				return nil
			}

			finding, err := s.Normalizer.Normalize(ctx, envelope.finding)
			if err != nil {
				releaseEnvelope(envelope)
				return sferr.Wrap(sferr.CodeNormalizeFailed, opRun, err, "normalize finding")
			}

			identity, err := s.Deduplicator.Fingerprint(ctx, finding)
			if err != nil {
				releaseEnvelope(envelope)
				return sferr.Wrap(sferr.CodeDedupFailed, opRun, err, "fingerprint finding")
			}

			finding.Identity = identity
			envelope.finding = finding

			select {
			case <-ctx.Done():
				releaseEnvelope(envelope)
				return ctx.Err()
			case out <- envelope:
			}
		}
	}
}

func (s Service) runDeduplicate(ctx context.Context, in <-chan *findingEnvelope, out chan<- *findingEnvelope, totalFindings *atomic.Int64) error {
	initialCapacity := s.Config.FindingBuffer
	if initialCapacity <= 0 {
		initialCapacity = 512
	}
	seen := make(map[evidence.Hash]struct{}, initialCapacity)

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case envelope, ok := <-in:
			if !ok {
				return nil
			}

			totalFindings.Add(1)
			key := envelope.finding.Identity.DedupKey
			if key.IsZero() {
				releaseEnvelope(envelope)
				return sferr.New(sferr.CodeDedupFailed, opRun, "missing dedup key")
			}
			if _, exists := seen[key]; exists {
				releaseEnvelope(envelope)
				continue
			}

			seen[key] = struct{}{}

			select {
			case <-ctx.Done():
				releaseEnvelope(envelope)
				return ctx.Err()
			case out <- envelope:
			}
		}
	}
}

func (s Service) correlate(ctx context.Context, compact []correlation.CompactFinding, representatives map[string]evidence.Finding) ([]evidence.RootCauseCluster, error) {
	if compactCapable, ok := s.Correlator.(compactCorrelator); ok {
		return compactCapable.CorrelateCompact(ctx, compact, representatives)
	}

	findings := make([]evidence.Finding, 0, len(representatives))
	for _, finding := range representatives {
		findings = append(findings, finding)
	}
	return s.Correlator.Correlate(ctx, findings)
}

type rehydratingIterator struct {
	cancel context.CancelFunc
	ch     chan rehydratedFinding
}

type rehydratedFinding struct {
	finding evidence.Finding
	err     error
}

func newRehydratingIterator(ctx context.Context, service Service, inputs []Input, selected map[string][]evidence.FindingRef) ports.FindingIterator {
	iterCtx, cancel := context.WithCancel(ctx)
	ch := make(chan rehydratedFinding, 32)
	go func() {
		defer close(ch)
		err := service.streamHydratedFindings(iterCtx, inputs, selected, func(finding evidence.Finding) error {
			select {
			case <-iterCtx.Done():
				return iterCtx.Err()
			case ch <- rehydratedFinding{finding: finding}:
				return nil
			}
		})
		if err != nil {
			select {
			case ch <- rehydratedFinding{err: err}:
			case <-iterCtx.Done():
				select {
				case ch <- rehydratedFinding{err: err}:
				default:
				}
			}
		}
	}()

	return &rehydratingIterator{
		cancel: cancel,
		ch:     ch,
	}
}

func (it *rehydratingIterator) Next(_ context.Context) (evidence.Finding, error) {
	item, ok := <-it.ch
	if !ok {
		return evidence.Finding{}, io.EOF
	}
	return item.finding, item.err
}

func (it *rehydratingIterator) Close() error {
	if it.cancel != nil {
		it.cancel()
	}
	return nil
}

func (s Service) streamHydratedFindings(ctx context.Context, inputs []Input, selected map[string][]evidence.FindingRef, emit func(evidence.Finding) error) error {
	for _, input := range inputs {
		if err := s.streamInput(ctx, input, selected, emit); err != nil {
			return err
		}
	}
	return nil
}

func (s Service) streamInput(ctx context.Context, input Input, selected map[string][]evidence.FindingRef, emit func(evidence.Finding) error) error {
	info, err := os.Stat(input.Path)
	if err != nil {
		return sferr.Wrap(sferr.CodeDiscoveryFailed, opRun, err, "stat input")
	}

	if !info.IsDir() {
		return s.streamSelectedFile(ctx, newDiscoveredFile(input.Path, sourceForPath(input.Source, input.Path)), selected[input.Path], emit)
	}

	return filepath.WalkDir(input.Path, func(path string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return sferr.Wrap(sferr.CodeDiscoveryFailed, opRun, walkErr, "walk input directory")
		}
		if d.IsDir() {
			return nil
		}
		return s.streamSelectedFile(ctx, newDiscoveredFile(path, sourceForPath(input.Source, path)), selected[path], emit)
	})
}

func (s Service) streamSelectedFile(ctx context.Context, file discoveredFile, refs []evidence.FindingRef, emit func(evidence.Finding) error) error {
	if len(refs) == 0 {
		return nil
	}

	parsers := selectParsers(s.Parsers, file.path)
	if len(parsers) == 0 {
		return sferr.New(sferr.CodeUnsupportedInput, opRun, "no parser supports input: "+file.path)
	}

	var lastErr error
	for _, parser := range parsers {
		handle, err := file.open()
		if err != nil {
			return sferr.Wrap(sferr.CodeIO, opRun, err, "open input")
		}

		seekable, ok := handle.(io.ReaderAt)
		if !ok {
			_ = handle.Close()
			return sferr.New(sferr.CodeIO, opRun, "input does not support random-access hydration")
		}

		err = hydrateSelectedFile(ctx, seekable, file, parser, refs, s.Normalizer, s.Deduplicator, emit)
		_ = handle.Close()
		if err == nil {
			return nil
		}
		if sferr.IsCode(err, sferr.CodeUnsupportedInput) {
			lastErr = err
			continue
		}
		return sferr.Wrap(sferr.CodeParseFailed, opRun, err, "reparse input")
	}

	if lastErr != nil {
		return sferr.Wrap(sferr.CodeParseFailed, opRun, lastErr, "reparse input")
	}
	return nil
}

func selectParsers(parsers []ports.Parser, filename string) []ports.Parser {
	if filename == "-" {
		return append([]ports.Parser(nil), parsers...)
	}
	name := strings.ToLower(filename)
	selected := make([]ports.Parser, 0, len(parsers))
	for _, parser := range parsers {
		if parser.Supports(name) {
			selected = append(selected, parser)
		}
	}
	return selected
}

func sourceForPath(source evidence.SourceDescriptor, path string) evidence.SourceDescriptor {
	source.URI = path
	return source
}

func releaseEnvelope(envelope *findingEnvelope) {
	envelope.finding = evidence.Finding{}
	envelope.ref = evidence.FindingRef{}
	envelopePool.Put(envelope)
}

func discoverInput(ctx context.Context, input Input, out chan<- discoveredFile, discoveredFiles *atomic.Int64) error {
	if input.Reader != nil {
		discoveredFiles.Add(1)
		select {
		case <-ctx.Done():
			return ctx.Err()
		case out <- discoveredInputFile(input):
			return nil
		}
	}

	info, err := os.Stat(input.Path)
	if err != nil {
		return sferr.Wrap(sferr.CodeDiscoveryFailed, opRun, err, "stat input")
	}

	if !info.IsDir() {
		discoveredFiles.Add(1)
		select {
		case <-ctx.Done():
			return ctx.Err()
		case out <- newDiscoveredFile(input.Path, sourceForPath(input.Source, input.Path)):
			return nil
		}
	}

	err = filepath.WalkDir(input.Path, func(path string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if d.IsDir() {
			return nil
		}
		discoveredFiles.Add(1)
		select {
		case <-ctx.Done():
			return ctx.Err()
		case out <- newDiscoveredFile(path, sourceForPath(input.Source, path)):
			return nil
		}
	})
	if err != nil {
		return sferr.Wrap(sferr.CodeDiscoveryFailed, opRun, err, "walk input directory")
	}

	return nil
}

func countCorrelated(clusters []evidence.RootCauseCluster) int {
	total := 0
	for _, cluster := range clusters {
		total += len(cluster.FindingIDs)
	}
	return total
}

func discoveredInputFile(input Input) discoveredFile {
	reader := input.Reader
	input.Reader = nil
	return discoveredFile{
		path:   input.Path,
		source: sourceForPath(input.Source, input.Path),
		open: func() (io.ReadCloser, error) {
			if reader == nil {
				return nil, sferr.New(sferr.CodeIO, opRun, "stdin input is no longer available")
			}
			current := reader
			reader = nil
			return current, nil
		},
	}
}

func newDiscoveredFile(path string, source evidence.SourceDescriptor) discoveredFile {
	return discoveredFile{
		path:   path,
		source: source,
		open: func() (io.ReadCloser, error) {
			return os.Open(path)
		},
	}
}

func primarySource(inputs []Input) evidence.SourceDescriptor {
	if len(inputs) == 0 {
		return evidence.SourceDescriptor{}
	}
	return inputs[0].Source
}

func newCountMatrix() map[evidence.SeverityLabel]map[evidence.Kind]int {
	return map[evidence.SeverityLabel]map[evidence.Kind]int{
		evidence.SeverityCritical: {},
		evidence.SeverityHigh:     {},
		evidence.SeverityMedium:   {},
		evidence.SeverityLow:      {},
		evidence.SeverityInfo:     {},
	}
}

func incrementCount(counts map[evidence.SeverityLabel]map[evidence.Kind]int, severity evidence.SeverityLabel, kind evidence.Kind) {
	if _, ok := counts[severity]; !ok {
		counts[severity] = make(map[evidence.Kind]int)
	}
	counts[severity][kind]++
}

func markSelected(selected map[string][]evidence.FindingRef, ref evidence.FindingRef) {
	selected[ref.Path] = append(selected[ref.Path], ref)
}

func updateRepresentative(representatives map[string]evidence.Finding, compact correlation.CompactFinding, finding evidence.Finding) {
	if compact.CorrelationKey == "" {
		return
	}
	id := compact.CorrelationType + "|" + compact.CorrelationKey
	current, exists := representatives[id]
	if !exists || current.Severity.Score < compact.SeverityScore {
		representatives[id] = finding
	}
}

func findingRefForParse(path string, meta ports.ParseMetadata) evidence.FindingRef {
	contextCopy := append([]byte(nil), meta.Context...)
	return evidence.FindingRef{
		Path:    path,
		Range:   meta.Range,
		Hint:    meta.Hint,
		Index:   meta.Index,
		Context: contextCopy,
	}
}

func hydrateSelectedFile(
	ctx context.Context,
	reader io.ReaderAt,
	file discoveredFile,
	parser ports.Parser,
	refs []evidence.FindingRef,
	normalizer ports.Normalizer,
	deduplicator ports.Deduplicator,
	emit func(evidence.Finding) error,
) error {
	for _, ref := range refs {
		finding, err := parser.Hydrate(ctx, ports.HydrateRequest{
			Source:   file.source,
			Filename: file.path,
			Reader:   reader,
			Meta: ports.ParseMetadata{
				Range:   ref.Range,
				Hint:    ref.Hint,
				Index:   ref.Index,
				Context: ref.Context,
			},
		})
		if err != nil {
			return err
		}

		normalized, err := normalizer.Normalize(ctx, finding)
		if err != nil {
			return err
		}
		identity, err := deduplicator.Fingerprint(ctx, normalized)
		if err != nil {
			return err
		}
		normalized.Identity = identity
		if err := emit(normalized); err != nil {
			return err
		}
	}

	return nil
}

type parserSinkFunc func(ctx context.Context, finding evidence.Finding, meta ports.ParseMetadata) error

func (f parserSinkFunc) WriteFinding(ctx context.Context, finding evidence.Finding, meta ports.ParseMetadata) error {
	return f(ctx, finding, meta)
}
