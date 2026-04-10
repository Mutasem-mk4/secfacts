package ports

import (
	"context"
	"github.com/axon/axon/internal/core/domain"
	"io"
)

// Parser defines how raw tool output is converted into the Internal Evidence Model.
type Parser interface {
	// Name returns the provider identifier of the parser (e.g., "sarif", "trivy").
	Name() string
	// Parse streams raw data from the reader and returns a channel of Evidence.
	Parse(ctx context.Context, r io.Reader) (<-chan domain.Evidence, <-chan error)
}

// Normalizer handles the deduplication and correlation pipeline for processed evidence.
type Normalizer interface {
	// Process consumes processed evidence and emits a consolidated/correlated stream.
	Process(ctx context.Context, in <-chan domain.Evidence) (<-chan domain.Evidence, <-chan error)
}

// Correlator transforms deduplicated findings into logical root-cause issues.
type Correlator interface {
	// Correlate takes a stream of deduplicated evidence and groups them into logical issues.
	Correlate(ctx context.Context, in <-chan domain.Evidence) (<-chan domain.Issue, <-chan error)
}

// Exporter writes the correlated Issues to the provided output destination.
type Exporter interface {
	// Export formats and writes the issues to the io.Writer.
	Export(ctx context.Context, w io.Writer, issues []domain.Issue) error
}

// Publisher defines the interface for sending evidence to a message broker.
type Publisher interface {
	// Publish sends evidence to the broker, sharding it based on its deterministic ID.
	Publish(ctx context.Context, ev domain.Evidence) error
}

// Subscriber defines the interface for receiving evidence from a message broker.
type Subscriber interface {
	// Subscribe returns a channel of evidence for the assigned shards.
	Subscribe(ctx context.Context, shards []int) (<-chan domain.Evidence, <-chan error)
}

// RemediationProvider defines the interface for LLM backends (OpenAI, Anthropic, Ollama).
type RemediationProvider interface {
	// Name returns the provider identifier.
	Name() string
	// SuggestFix requests a remediation proposal from the AI backend.
	SuggestFix(ctx context.Context, issue domain.Issue) (*domain.RemediationProposal, error)
}

// RemediationService defines the orchestration logic for generating and applying fixes.
type RemediationService interface {
	// AnalyzeIssue prepares the context and calls the provider to get a fix.
	AnalyzeIssue(ctx context.Context, issue domain.Issue) (*domain.RemediationProposal, error)
	// ApplyFix executes the suggested code changes if the user confirms.
	ApplyFix(ctx context.Context, proposal domain.RemediationProposal) error
}

// Sink defines the interface for external integrations (Jira, Slack, etc.).
type Sink interface {
	// Name returns the identifier of the sink.
	Name() string
	// Emit sends a single correlated issue to the external destination.
	Emit(ctx context.Context, issue domain.Issue) error
}
