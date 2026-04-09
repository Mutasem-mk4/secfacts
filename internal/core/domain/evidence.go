package domain

import "time"

// FindingType categorizes the security finding.
type FindingType string

const (
	TypeSAST    FindingType = "SAST"
	TypeDAST    FindingType = "DAST"
	TypeSCA     FindingType = "SCA"
	TypeCloud   FindingType = "CLOUD"
	TypeSecrets FindingType = "SECRETS"
)

// Severity represents a canonical 0.0-10.0 scale for cross-tool mapping.
type Severity struct {
	Score  float32 `json:"score"`
	Label  string  `json:"label"`
	Vector string  `json:"vector,omitempty"`
}

// Vulnerability provides detailed metadata about the identified threat.
type Vulnerability struct {
	ID          string   `json:"id"`
	Description string   `json:"description,omitempty"`
	CWE         []string `json:"cwe,omitempty"`
	Aliases     []string `json:"aliases,omitempty"`
}

// Location pinpoint the finding in the target resource.
type Location struct {
	Path      string `json:"path"`
	StartLine int    `json:"start_line,omitempty"`
	StartCol  int    `json:"start_col,omitempty"`
	EndLine   int    `json:"end_line,omitempty"`
	EndCol    int    `json:"end_col,omitempty"`
	Snippet   string `json:"snippet,omitempty"`
}

// Resource identifies the affected component.
type Resource struct {
	URI     string `json:"uri"` // Normalized PURL or Path
	Name    string `json:"name"`
	Version string `json:"version,omitempty"`
	Type    string `json:"type,omitempty"`
}

// AckFunc is a callback for manual message acknowledgment.
type AckFunc func() error

// Evidence is the core IEM struct for axon normalization.
type Evidence struct {
	ID            string            `json:"id"`            // Deterministic hash (Normalized/Fuzzy)
	Provider      string            `json:"provider"`      // Tool name
	Type          FindingType       `json:"type"`          // Finding classification
	Vulnerability Vulnerability     `json:"vulnerability"` // Finding metadata
	Resource      Resource          `json:"resource"`      // Affected asset
	Location      *Location         `json:"location,omitempty"`
	Severity      Severity          `json:"severity"`          // Canonical 0-10 score
	Details       map[string]string `json:"details,omitempty"` // Raw tool-specific data
	Timestamp     time.Time         `json:"timestamp"`         // Discovery timestamp
	Ack           AckFunc           `json:"-"`                 // Ack callback (not serialized)
}
