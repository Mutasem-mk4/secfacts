package evidence

import "time"

const SchemaVersion = "axon.iem/v1alpha1"

type Kind string

const (
	KindSAST    Kind = "sast"
	KindDAST    Kind = "dast"
	KindSCA     Kind = "sca"
	KindCloud   Kind = "cloud"
	KindSecrets Kind = "secrets"
)

type Document struct {
	SchemaVersion string
	GeneratedAt   time.Time
	Source        SourceDescriptor
	Summary       Summary
	Findings      []Finding
	Correlations  []RootCauseCluster
}

type Summary struct {
	TotalFindings      int
	UniqueFindings     int
	CorrelatedFindings int
}

type SourceDescriptor struct {
	Provider      string
	ToolName      string
	ToolVersion   string
	Format        string
	FormatVersion string
	URI           string
	GeneratedAt   time.Time
}

type Finding struct {
	SchemaVersion     string
	ID                string
	Kind              Kind
	Title             string
	Description       string
	Severity          Severity
	Confidence        Confidence
	Rule              Rule
	PrimaryLocation   Location
	Locations         []Location
	Artifact          Artifact
	Package           *Package
	Image             *Image
	Cloud             *CloudResource
	Secret            *Secret
	Vulnerability     *Vulnerability
	References        []Reference
	Tags              []string
	Source            SourceRecord
	Identity          Identity
	RootCauseHints    []RootCauseHint
	Annotations       map[string]string
	FirstObservedAt   *time.Time
	LastObservedAt    *time.Time
	RawRecordChecksum string
}

type Severity struct {
	Score  float64
	Label  SeverityLabel
	Vector string
}

type SeverityLabel string

const (
	SeverityInfo     SeverityLabel = "info"
	SeverityLow      SeverityLabel = "low"
	SeverityMedium   SeverityLabel = "medium"
	SeverityHigh     SeverityLabel = "high"
	SeverityCritical SeverityLabel = "critical"
)

type Confidence string

const (
	ConfidenceUnknown Confidence = "unknown"
	ConfidenceLow     Confidence = "low"
	ConfidenceMedium  Confidence = "medium"
	ConfidenceHigh    Confidence = "high"
)

type Rule struct {
	ID          string
	Name        string
	Category    string
	Subcategory string
}

type Location struct {
	URI           string
	Line          int
	Column        int
	EndLine       int
	EndColumn     int
	SnippetDigest string
}

type Artifact struct {
	Type      string
	Name      string
	Namespace string
	Version   string
}

type Package struct {
	Type            string
	Name            string
	Version         string
	FixedVersion    string
	Language        string
	PackageURL      string
	DependencyChain []string
}

type Image struct {
	Registry   string
	Repository string
	Tag        string
	Digest     string
	BaseDigest string
	BaseName   string
}

type CloudResource struct {
	Provider    string
	AccountID   string
	Region      string
	Service     string
	ResourceID  string
	ResourceARN string
}

type Secret struct {
	Type        string
	Provider    string
	Fingerprint string
	Redacted    string
}

type Vulnerability struct {
	ID             string
	Aliases        []string
	CWE            []string
	CVSSVector     string
	CVSSScore      float64
	AttackVector   string
	Exploitability string
}

type Reference struct {
	Type string
	URL  string
	ID   string
}

type SourceRecord struct {
	Provider       string
	Scanner        string
	ScannerVersion string
	FindingID      string
	RunID          string
}

type Identity struct {
	DedupKey      Hash
	NaturalKey    Hash
	FingerprintV1 Hash
}

type RootCauseHint struct {
	Type  string
	Key   string
	Value string
}

type RootCauseCluster struct {
	ID             string
	Key            string
	Type           string
	Title          string
	FindingIDs     []string
	Representative Finding
}
