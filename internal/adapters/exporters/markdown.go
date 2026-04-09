package exporters

import (
	"context"
	"fmt"
	"io"
	"sort"
	"time"

	"github.com/axon/axon/internal/core/domain"
)

// MarkdownExporter implements ports.Exporter for Markdown report generation.
type MarkdownExporter struct{}

func NewMarkdownExporter() *MarkdownExporter {
	return &MarkdownExporter{}
}

// Export writes the issues to the io.Writer in a professional Markdown format.
func (e *MarkdownExporter) Export(ctx context.Context, w io.Writer, issues []domain.Issue) error {
	// Sort issues by severity (descending)
	sort.Slice(issues, func(i, j int) bool {
		return issues[i].Severity.Score > issues[j].Severity.Score
	})

	fmt.Fprintln(w, "# Axon Security Scan Report")
	fmt.Fprintf(w, "Generated on: %s\n\n", time.Now().Format(time.RFC1123))

	fmt.Fprintln(w, "## Executive Summary")
	fmt.Fprintf(w, "- Total Logical Issues: %d\n", len(issues))

	severityCounts := make(map[string]int)
	for _, issue := range issues {
		severityCounts[issue.Severity.Label]++
	}

	for label, count := range severityCounts {
		fmt.Fprintf(w, "- %s: %d\n", label, count)
	}
	fmt.Fprintln(w)

	fmt.Fprintln(w, "## Detailed Issues")
	for _, issue := range issues {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
			fmt.Fprintf(w, "### %s (Severity: %.1f)\n", issue.Type, issue.Severity.Score)
			fmt.Fprintf(w, "**Target:** `%s`\n\n", issue.Target.URI)
			fmt.Fprintf(w, "**Actionable Advice:** %s\n\n", issue.Remediation)

			fmt.Fprintln(w, "| Tool | Finding ID | Severity | Description |")
			fmt.Fprintln(w, "|---|---|---|---|")
			for _, f := range issue.Findings {
				fmt.Fprintf(w, "| %s | %s | %.1f | %s |\n",
					f.Provider, f.Vulnerability.ID, f.Severity.Score, f.Vulnerability.Description)
			}
			fmt.Fprintln(w)
		}
	}

	return nil
}
