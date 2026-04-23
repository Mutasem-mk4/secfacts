package evidence

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
)

// appendNormalized trims space and lowercases the string s, then appends it to buf.
// It also prepends a '|' separator if this is not the first element.
func appendNormalized(buf []byte, s string, isFirst bool) []byte {
	if !isFirst {
		buf = append(buf, '|')
	}

	s = strings.TrimSpace(s)
	s = strings.ToLower(s)

	buf = append(buf, s...)
	return buf
}

func DedupMaterial(f Finding) string {
	// Optimization: Pre-allocate a 128-byte buffer to construct the deduplication string.
	// This avoids allocating an intermediate []string slice and the overhead of strings.Join,
	// reducing memory allocations during high-velocity processing.
	buf := make([]byte, 0, 128)

	buf = appendNormalized(buf, string(f.Kind), true)
	buf = appendNormalized(buf, f.Rule.ID, false)
	buf = append(buf, '|')
	buf = append(buf, normalizedVulnerabilityID(f)...)
	buf = appendNormalized(buf, f.PackageName(), false)
	buf = appendNormalized(buf, f.PackageVersion(), false)
	buf = appendNormalized(buf, f.PrimaryLocation.URI, false)
	buf = appendNormalized(buf, f.Artifact.Name, false)
	buf = appendNormalized(buf, f.CloudResourceID(), false)
	buf = appendNormalized(buf, f.SecretFingerprint(), false)

	return string(buf)
}

func DedupHash(f Finding) string {
	sum := sha256.Sum256([]byte(DedupMaterial(f)))
	return hex.EncodeToString(sum[:])
}

func (f Finding) PackageName() string {
	if f.Package == nil {
		return ""
	}

	return f.Package.Name
}

func (f Finding) PackageVersion() string {
	if f.Package == nil {
		return ""
	}

	return f.Package.Version
}

func (f Finding) CloudResourceID() string {
	if f.Cloud == nil {
		return ""
	}

	if f.Cloud.ResourceARN != "" {
		return f.Cloud.ResourceARN
	}

	return f.Cloud.ResourceID
}

func (f Finding) SecretFingerprint() string {
	if f.Secret == nil {
		return ""
	}

	return f.Secret.Fingerprint
}

func normalizedVulnerabilityID(f Finding) string {
	if f.Vulnerability == nil {
		return ""
	}

	return strings.ToLower(strings.TrimSpace(f.Vulnerability.ID))
}
