package services

import (
	"context"
	"fmt"
	"io"
	"os"
	"text/tabwriter"

	"github.com/mattn/go-isatty"
	"github.com/axon/axon/internal/core/domain"
	"github.com/axon/axon/internal/core/ports"
	"github.com/axon/axon/pkg/errors"
)

// Pipeline coordinates the end-to-end security evidence processing flow.
type Pipeline struct {
	parser     ports.Parser
	normalizer ports.Normalizer
	correlator ports.Correlator
	exporter   ports.Exporter
	failScore  float32
}

// PipelineOption defines a functional option for configuring the Pipeline.
type PipelineOption func(*Pipeline)

func WithParser(p ports.Parser) PipelineOption {
	return func(pipeline *Pipeline) {
		pipeline.parser = p
	}
}

func WithNormalizer(n ports.Normalizer) PipelineOption {
	return func(pipeline *Pipeline) {
		pipeline.normalizer = n
	}
}

func WithCorrelator(c ports.Correlator) PipelineOption {
	return func(pipeline *Pipeline) {
		pipeline.correlator = c
	}
}

func WithExporter(e ports.Exporter) PipelineOption {
	return func(pipeline *Pipeline) {
		pipeline.exporter = e
	}
}

func WithFailScore(score float32) PipelineOption {
	return func(pipeline *Pipeline) {
		pipeline.failScore = score
	}
}

// NewPipeline creates a new Pipeline with the provided options.
func NewPipeline(opts ...PipelineOption) *Pipeline {
	p := &Pipeline{}
	for _, opt := range opts {
		opt(p)
	}
	return p
}

// Run executes the complete orchestration pipeline.
func (p *Pipeline) Run(ctx context.Context, input io.Reader, output io.Writer) error {
	// 1. Parsing
	evChan, pErrChan := p.parser.Parse(ctx, input)

	// 2. Normalization (Deduplication)
	normChan, nErrChan := p.normalizer.Process(ctx, evChan)

	// 3. Correlation (Reasoning)
	issueChan, cErrChan := p.correlator.Correlate(ctx, normChan)

	// Collect issues
	var issues []domain.Issue
	for issue := range issueChan {
		issues = append(issues, issue)
	}

	// Error handling (Check channels for errors)
	select {
	case err := <-pErrChan:
		if err != nil {
			return err
		}
	case err := <-nErrChan:
		if err != nil {
			return err
		}
	case err := <-cErrChan:
		if err != nil {
			return err
		}
	default:
		// No immediate errors
	}

	// 4. Print Terminal Summary (Directly to Stderr for high visibility)
	p.printTerminalSummary(os.Stderr, issues)

	// 5. Exporting
	if err := p.exporter.Export(ctx, output, issues); err != nil {
		return err
	}

	// 6. Threshold Check
	if p.failScore > 0 {
		for _, issue := range issues {
			if issue.Severity.Score >= p.failScore {
				return errors.NewDomainError(errors.ErrCodeThresholdExceeded,
					fmt.Sprintf("severity threshold exceeded: found issue with score %.1f (limit: %.1f)",
						issue.Severity.Score, p.failScore), nil)
			}
		}
	}

	return nil
}

func (p *Pipeline) printTerminalSummary(w io.Writer, issues []domain.Issue) {
	isTerminal := false
	if f, ok := w.(*os.File); ok {
		isTerminal = isatty.IsTerminal(f.Fd()) || isatty.IsCygwinTerminal(f.Fd())
	}

	const (
		twReset  = "\xff\033[0m\xff"
		twRed    = "\xff\033[31m\xff"
		twYellow = "\xff\033[33m\xff"
		colorReset = "\033[0m"
		colorCyan  = "\033[36m"
		colorRedPlain = "\033[31m"
		colorBold  = "\033[1m"
	)

	if isTerminal {
		fmt.Fprintf(w, "\n%s%s=== AXON SCAN SUMMARY ===%s\n", colorBold, colorCyan, colorReset)
	} else {
		fmt.Fprintf(w, "\n=== AXON SCAN SUMMARY ===\n")
	}

	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', tabwriter.StripEscape)

	severityCounts := make(map[string]int)
	var maxScore float32
	for _, issue := range issues {
		severityCounts[issue.Severity.Label]++
		if issue.Severity.Score > maxScore {
			maxScore = issue.Severity.Score
		}
	}

	fmt.Fprintf(tw, "Total Issues Found:\t%d\n", len(issues))
	if isTerminal {
		fmt.Fprintf(tw, "Critical Severity:\t%s🚨 %d%s\n", twRed, severityCounts["critical"], twReset)
		fmt.Fprintf(tw, "High Severity:\t%s🔴 %d%s\n", twYellow, severityCounts["high"], twReset)
	} else {
		fmt.Fprintf(tw, "Critical Severity:\t🚨 %d\n", severityCounts["critical"])
		fmt.Fprintf(tw, "High Severity:\t🔴 %d\n", severityCounts["high"])
	}
	fmt.Fprintf(tw, "Medium Severity:\t🟡 %d\n", severityCounts["medium"])
	fmt.Fprintf(tw, "Highest Score:\t%.1f\n", maxScore)

	tw.Flush()

	if p.failScore > 0 {
		status := "PASS"
		color := colorCyan
		icon := "✅"
		if maxScore >= p.failScore {
			status = "FAIL"
			color = colorRedPlain
			icon = "❌"
		}

		if isTerminal {
			fmt.Fprintf(w, "\nThreshold Status: %s %s%s%s (Limit: %.1f)\n", icon, color, status, colorReset, p.failScore)
		} else {
			fmt.Fprintf(w, "\nThreshold Status: %s %s (Limit: %.1f)\n", icon, status, p.failScore)
		}
	}
	fmt.Fprintln(w)
}
