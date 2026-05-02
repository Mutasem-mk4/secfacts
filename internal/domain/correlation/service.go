package correlation

import (
	"context"
	"sort"

	"github.com/axon/axon/internal/domain/evidence"
)

const opCorrelate = "correlation.Service.Correlate"

type Service struct{}

func (Service) Correlate(_ context.Context, findings []evidence.Finding) ([]evidence.RootCauseCluster, error) {
	if len(findings) == 0 {
		return nil, nil
	}

	compact := make([]CompactFinding, 0, len(findings))
	representatives := make(map[string]evidence.Finding, len(findings)/4+1)
	// ⚡ Bolt: Use index-based pointer semantics to avoid copying large structs in loops
	for i := range findings {
		finding := &findings[i]
		ref := evidence.FindingRef{Path: finding.Source.Provider}
		item := Compact(*finding, ref)
		compact = append(compact, item)
		updateRepresentative(representatives, item, *finding)
	}

	return correlateCompact(compact, representatives), nil
}

func (Service) CorrelateCompact(_ context.Context, compact []CompactFinding, representatives map[string]evidence.Finding) ([]evidence.RootCauseCluster, error) {
	return correlateCompact(compact, representatives), nil
}

func correlateCompact(compact []CompactFinding, representatives map[string]evidence.Finding) []evidence.RootCauseCluster {
	if len(compact) == 0 {
		return nil
	}

	initialCapacity := len(compact)/4 + 1
	clusterIndex := make(map[string]int, initialCapacity)
	clusters := make([]evidence.RootCauseCluster, 0, initialCapacity)

	for _, item := range compact {
		if item.CorrelationKey == "" {
			continue
		}

		id := item.CorrelationType + "|" + item.CorrelationKey
		index, exists := clusterIndex[id]
		if !exists {
			index = len(clusters)
			clusterIndex[id] = index
			clusters = append(clusters, evidence.RootCauseCluster{
				ID:         id,
				Key:        item.CorrelationKey,
				Type:       item.CorrelationType,
				Title:      item.CorrelationTitle,
				FindingIDs: make([]string, 0, 4),
			})
		}

		cluster := &clusters[index]
		cluster.FindingIDs = append(cluster.FindingIDs, item.ID)
		cluster.Representative = representatives[id]
	}

	result := clusters[:0]
	for _, cluster := range clusters {
		if len(cluster.FindingIDs) < 2 {
			continue
		}

		sort.Strings(cluster.FindingIDs)
		result = append(result, cluster)
	}

	sort.Slice(result, func(i int, j int) bool {
		if result[i].Type != result[j].Type {
			return result[i].Type < result[j].Type
		}

		return result[i].Key < result[j].Key
	})

	return result
}

func correlationKey(f evidence.Finding) (string, string, string) {
	if f.Kind == evidence.KindSCA && f.Package != nil && f.Vulnerability != nil {
		vulnerabilityID := f.Vulnerability.ID
		if vulnerabilityID == "" && len(f.Vulnerability.Aliases) > 0 {
			vulnerabilityID = f.Vulnerability.Aliases[0]
		}
		if vulnerabilityID != "" && f.Package.Name != "" {
			key := vulnerabilityID + "|" + f.Package.Name
			return key, "sca_package_vulnerability", "dependency vulnerability: " + key
		}
	}

	if f.Kind == evidence.KindSAST && f.Rule.ID != "" && f.PrimaryLocation.URI != "" {
		key := f.Rule.ID + "|" + f.PrimaryLocation.URI
		return key, "sast_rule_file", "code path: " + key
	}

	for _, hint := range f.RootCauseHints {
		if hint.Type == "" || hint.Value == "" {
			continue
		}

		return hint.Value, hint.Type, hint.Type + ": " + hint.Value
	}

	if f.Image != nil && f.Image.BaseDigest != "" {
		return f.Image.BaseDigest, "base_image", "base image: " + f.Image.BaseDigest
	}

	if f.Package != nil && f.Vulnerability != nil {
		key := f.Package.PackageURL
		if key == "" {
			key = f.Package.Name
		}
		if key != "" {
			return key, "dependency", "dependency: " + key
		}
	}

	return "", "", ""
}

func updateRepresentative(representatives map[string]evidence.Finding, compact CompactFinding, finding evidence.Finding) {
	if compact.CorrelationKey == "" {
		return
	}

	id := compact.CorrelationType + "|" + compact.CorrelationKey
	current, exists := representatives[id]
	if !exists || current.Severity.Score < compact.SeverityScore {
		representatives[id] = finding
	}
}
