package evidence

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"unicode"
	"unicode/utf8"
)

func writeNormalizedField(b *strings.Builder, s string) {
	s = strings.TrimSpace(s)
	for i := 0; i < len(s); {
		c := s[i]
		if c < utf8.RuneSelf {
			if 'A' <= c && c <= 'Z' {
				b.WriteByte(c + ('a' - 'A'))
			} else {
				b.WriteByte(c)
			}
			i++
		} else {
			r, size := utf8.DecodeRuneInString(s[i:])
			b.WriteRune(unicode.ToLower(r))
			i += size
		}
	}
}

func DedupMaterial(f Finding) string {
	var b strings.Builder
	b.Grow(128)

	writeNormalizedField(&b, string(f.Kind))
	b.WriteByte('|')
	writeNormalizedField(&b, f.Rule.ID)
	b.WriteByte('|')

	var vulnID string
	if f.Vulnerability != nil {
		vulnID = f.Vulnerability.ID
	}
	writeNormalizedField(&b, vulnID)
	b.WriteByte('|')

	writeNormalizedField(&b, f.PackageName())
	b.WriteByte('|')
	writeNormalizedField(&b, f.PackageVersion())
	b.WriteByte('|')
	writeNormalizedField(&b, f.PrimaryLocation.URI)
	b.WriteByte('|')
	writeNormalizedField(&b, f.Artifact.Name)
	b.WriteByte('|')
	writeNormalizedField(&b, f.CloudResourceID())
	b.WriteByte('|')
	writeNormalizedField(&b, f.SecretFingerprint())

	return b.String()
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
