package correlation

import "github.com/secfacts/secfacts/internal/domain/evidence"

type CompactFinding struct {
	ID               string
	SeverityScore    float64
	CorrelationKey   string
	CorrelationType  string
	CorrelationTitle string
	Kind             evidence.Kind
	SeverityLabel    evidence.SeverityLabel
	Ref              evidence.FindingRef
}

func Compact(f evidence.Finding, ref evidence.FindingRef) CompactFinding {
	key, kind, title := correlationKey(f)
	return CompactFinding{
		ID:               f.CanonicalID(),
		SeverityScore:    f.Severity.Score,
		SeverityLabel:    f.Severity.Label,
		Kind:             f.Kind,
		CorrelationKey:   key,
		CorrelationType:  kind,
		CorrelationTitle: title,
		Ref:              ref,
	}
}
