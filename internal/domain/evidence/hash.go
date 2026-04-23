package evidence

import (
	"crypto/sha256"
	"encoding/hex"
	"sync"
)

func isSpace(c byte) bool {
	return c == ' ' || c == '\t' || c == '\n' || c == '\r'
}

func writeNormalized(b []byte, s string) []byte {
	start := 0
	for start < len(s) && isSpace(s[start]) {
		start++
	}
	end := len(s)
	for end > start && isSpace(s[end-1]) {
		end--
	}

	for i := start; i < end; i++ {
		c := s[i]
		if c >= 'A' && c <= 'Z' {
			c += 'a' - 'A'
		}
		b = append(b, c)
	}
	return b
}

var dedupBufPool = sync.Pool{
	New: func() interface{} {
		b := make([]byte, 0, 512)
		return &b
	},
}

func fillDedupBuffer(b []byte, f Finding) []byte {
	b = writeNormalized(b, string(f.Kind))
	b = append(b, '|')
	b = writeNormalized(b, f.Rule.ID)
	b = append(b, '|')
	if f.Vulnerability != nil {
		b = writeNormalized(b, f.Vulnerability.ID)
	}
	b = append(b, '|')
	if f.Package != nil {
		b = writeNormalized(b, f.Package.Name)
	}
	b = append(b, '|')
	if f.Package != nil {
		b = writeNormalized(b, f.Package.Version)
	}
	b = append(b, '|')
	b = writeNormalized(b, f.PrimaryLocation.URI)
	b = append(b, '|')
	b = writeNormalized(b, f.Artifact.Name)
	b = append(b, '|')
	if f.Cloud != nil {
		if f.Cloud.ResourceARN != "" {
			b = writeNormalized(b, f.Cloud.ResourceARN)
		} else {
			b = writeNormalized(b, f.Cloud.ResourceID)
		}
	}
	b = append(b, '|')
	if f.Secret != nil {
		b = writeNormalized(b, f.Secret.Fingerprint)
	}
	return b
}

func DedupMaterial(f Finding) string {
	ptr := dedupBufPool.Get().(*[]byte)
	b := (*ptr)[:0]

	b = fillDedupBuffer(b, f)

	res := string(b)
	dedupBufPool.Put(ptr)
	return res
}

func DedupHash(f Finding) string {
	ptr := dedupBufPool.Get().(*[]byte)
	b := (*ptr)[:0]

	b = fillDedupBuffer(b, f)

	sum := sha256.Sum256(b)
	dedupBufPool.Put(ptr)
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

// normalizedVulnerabilityID is removed because its logic is inlined in fillDedupBuffer.
