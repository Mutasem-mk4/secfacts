package evidence

import (
	"crypto/sha256"
	"sort"
	"strconv"
	"sync"
)

const (
	identityNaturalKeyVersion = "natural/v1"
	identityFingerprintV1     = "fingerprint/v1"
	identityDedupKeyVersion   = "dedup/v1"
)

type IdentityBuilder interface {
	Build(f Finding) Identity
	BuildNaturalKey(f Finding) Hash
	BuildFingerprintV1(f Finding) Hash
	BuildDedupKey(f Finding) Hash
}

type DefaultIdentityBuilder struct{}

var (
	hexDecodeTable [256]byte
	hexValidTable  [256]byte
)

var identityBufferPool = sync.Pool{
	New: func() any {
		buffer := make([]byte, 0, 256)
		return &buffer
	},
}

func init() {
	for ch := byte('0'); ch <= '9'; ch++ {
		hexDecodeTable[ch] = ch - '0'
		hexValidTable[ch] = 1
	}

	for ch := byte('a'); ch <= 'f'; ch++ {
		hexDecodeTable[ch] = ch - 'a' + 10
		hexValidTable[ch] = 1
	}

	for ch := byte('A'); ch <= 'F'; ch++ {
		hexDecodeTable[ch] = ch - 'A' + 10
		hexValidTable[ch] = 1
	}
}

func (DefaultIdentityBuilder) Build(f Finding) Identity {
	material := buildNaturalKeyMaterial(f)
	defer releaseIdentityBuffer(material)

	fingerprint := hashIdentityBytes(identityFingerprintV1, material)

	return Identity{
		NaturalKey:    hashIdentityBytes(identityNaturalKeyVersion, material),
		FingerprintV1: fingerprint,
		DedupKey:      hashIdentityBytes(identityDedupKeyVersion, fingerprint[:]),
	}
}

func (DefaultIdentityBuilder) BuildNaturalKey(f Finding) Hash {
	material := buildNaturalKeyMaterial(f)
	defer releaseIdentityBuffer(material)

	return hashIdentityBytes(identityNaturalKeyVersion, material)
}

func (DefaultIdentityBuilder) BuildFingerprintV1(f Finding) Hash {
	material := buildNaturalKeyMaterial(f)
	defer releaseIdentityBuffer(material)

	return hashIdentityBytes(identityFingerprintV1, material)
}

func (b DefaultIdentityBuilder) BuildDedupKey(f Finding) Hash {
	fingerprint := b.BuildFingerprintV1(f)
	return hashIdentityBytes(identityDedupKeyVersion, fingerprint[:])
}

func buildNaturalKeyMaterial(f Finding) []byte {
	buffer := acquireIdentityBufferWithCap(estimateNaturalKeyCapacity(f))

	switch f.Kind {
	case KindSAST:
		appendNormalizedSegment(buffer, string(f.Kind))
		appendNormalizedSegment(buffer, f.Rule.ID)
		appendNormalizedPathSegment(buffer, f.PrimaryLocation.URI)
		appendNormalizedLineSegment(buffer, f.PrimaryLocation.Line)
		appendNormalizedSegment(buffer, annotationValue(f, "sast.source"))
		appendNormalizedSegment(buffer, annotationValue(f, "sast.sink"))
		appendNormalizedSegment(buffer, annotationValue(f, "sast.function"))
		appendNormalizedSegment(buffer, f.PrimaryLocation.SnippetDigest)
	case KindSCA:
		appendNormalizedSegment(buffer, string(f.Kind))
		appendNormalizedSegment(buffer, vulnerabilityID(f))
		appendNormalizedSegment(buffer, packageURL(f))
		appendNormalizedSegment(buffer, f.PackageName())
		appendNormalizedSegment(buffer, f.PackageVersion())
		appendNormalizedSegment(buffer, f.FixedVersion())
	default:
		appendNormalizedSegment(buffer, string(f.Kind))
		appendNormalizedSegment(buffer, f.Rule.ID)
		appendNormalizedSegment(buffer, vulnerabilityID(f))
		appendNormalizedPathSegment(buffer, f.PrimaryLocation.URI)
		appendNormalizedLineSegment(buffer, f.PrimaryLocation.Line)
		appendNormalizedSegment(buffer, f.Artifact.Name)
		appendNormalizedSegment(buffer, f.CloudResourceID())
		appendNormalizedSegment(buffer, f.SecretFingerprint())
		appendNormalizedSegment(buffer, imageDigest(f))
		appendNormalizedSegment(buffer, packageURL(f))
		appendNormalizedSegment(buffer, f.PrimaryLocation.SnippetDigest)
	}

	return *buffer
}

func hashIdentityBytes(version string, material []byte) Hash {
	return Hash(sha256WithVersion(version, material))
}

func sha256WithVersion(version string, material []byte) [32]byte {
	buffer := acquireIdentityBufferWithCap(len(version) + 1 + len(material))
	defer releaseIdentityBuffer(*buffer)

	*buffer = append(*buffer, version...)
	*buffer = append(*buffer, '|')
	*buffer = append(*buffer, material...)

	return sha256.Sum256(*buffer)
}


func acquireIdentityBufferWithCap(n int) *[]byte {
	buffer := identityBufferPool.Get().(*[]byte)
	if cap(*buffer) < n {
		*buffer = make([]byte, 0, n)
	}
	*buffer = (*buffer)[:0]
	return buffer
}

func releaseIdentityBuffer(buffer []byte) {
	buffer = buffer[:0]
	identityBufferPool.Put(&buffer)
}

func appendNormalizedSegment(buffer *[]byte, value string) {
	out := *buffer
	if len(out) > 0 {
		out = append(out, '|')
	}

	seenNonSpace := false
	pendingSpaces := 0

	for i, n := 0, len(value); i < n; i++ {
		ch := value[i]
		if !seenNonSpace && isIdentitySpace(ch) {
			continue
		}

		if isIdentitySpace(ch) {
			pendingSpaces++
			continue
		}

		seenNonSpace = true
		for ; pendingSpaces > 0; pendingSpaces-- {
			out = append(out, ' ')
		}
		if ch >= 'A' && ch <= 'Z' {
			ch += 'a' - 'A'
		}

		out = append(out, ch)
	}

	*buffer = out
}

func appendNormalizedPathSegment(buffer *[]byte, value string) {
	out := *buffer
	if len(out) > 0 {
		out = append(out, '|')
	}

	seenNonSpace := false
	pendingSpaces := 0

	for i, n := 0, len(value); i < n; i++ {
		ch := value[i]
		if !seenNonSpace && isIdentitySpace(ch) {
			continue
		}

		if isIdentitySpace(ch) {
			pendingSpaces++
			continue
		}

		seenNonSpace = true
		for ; pendingSpaces > 0; pendingSpaces-- {
			out = append(out, ' ')
		}
		if ch == '\\' {
			ch = '/'
		}
		if ch >= 'A' && ch <= 'Z' {
			ch += 'a' - 'A'
		}

		out = append(out, ch)
	}

	*buffer = out
}

func appendNormalizedLineSegment(buffer *[]byte, line int) {
	if len(*buffer) > 0 {
		*buffer = append(*buffer, '|')
	}

	if line <= 0 {
		return
	}

	*buffer = strconv.AppendInt(*buffer, int64(line), 10)
}

func estimateNaturalKeyCapacity(f Finding) int {
	capacity := 32

	switch f.Kind {
	case KindSAST:
		capacity += len(f.Rule.ID)
		capacity += len(f.PrimaryLocation.URI)
		capacity += len(f.PrimaryLocation.SnippetDigest)
		capacity += len(annotationValue(f, "sast.source"))
		capacity += len(annotationValue(f, "sast.sink"))
		capacity += len(annotationValue(f, "sast.function"))
	case KindSCA:
		capacity += len(vulnerabilityID(f))
		capacity += len(packageURL(f))
		capacity += len(f.PackageName())
		capacity += len(f.PackageVersion())
		capacity += len(f.FixedVersion())
	default:
		capacity += len(f.Rule.ID)
		capacity += len(vulnerabilityID(f))
		capacity += len(f.PrimaryLocation.URI)
		capacity += len(f.Artifact.Name)
		capacity += len(f.CloudResourceID())
		capacity += len(f.SecretFingerprint())
		capacity += len(imageDigest(f))
		capacity += len(packageURL(f))
		capacity += len(f.PrimaryLocation.SnippetDigest)
	}

	return capacity
}

func isIdentitySpace(ch byte) bool {
	switch ch {
	case ' ', '\n', '\r', '\t':
		return true
	default:
		return false
	}
}

func annotationValue(f Finding, key string) string {
	if len(f.Annotations) == 0 {
		return ""
	}

	return f.Annotations[key]
}

func vulnerabilityID(f Finding) string {
	if f.Vulnerability == nil {
		return ""
	}

	if f.Vulnerability.ID != "" {
		return f.Vulnerability.ID
	}

	if len(f.Vulnerability.Aliases) == 0 {
		return ""
	}

	aliases := append([]string(nil), f.Vulnerability.Aliases...)
	sort.Strings(aliases)

	return aliases[0]
}

func packageURL(f Finding) string {
	if f.Package == nil {
		return ""
	}

	return f.Package.PackageURL
}

func imageDigest(f Finding) string {
	if f.Image == nil {
		return ""
	}

	if f.Image.Digest != "" {
		return f.Image.Digest
	}

	return f.Image.BaseDigest
}

func (f Finding) FixedVersion() string {
	if f.Package == nil {
		return ""
	}

	return f.Package.FixedVersion
}
