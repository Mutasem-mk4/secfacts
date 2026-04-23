package evidence

import (
	"testing"
)

func BenchmarkDedupHashOld(b *testing.B) {
	f := Finding{
		Kind: "SCA",
		Rule: Rule{ID: "CVE-2023-1234"},
		Vulnerability: &Vulnerability{ID: " CVE-2023-1234 "},
		Package: &Package{Name: "  test-package  ", Version: " 1.2.3 "},
		PrimaryLocation: Location{URI: "  /path/to/file.go  "},
		Artifact: Artifact{Name: "  test-artifact  "},
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		DedupHash(f)
	}
}

func BenchmarkDedupMaterialOld(b *testing.B) {
	f := Finding{
		Kind: "SCA",
		Rule: Rule{ID: "CVE-2023-1234"},
		Vulnerability: &Vulnerability{ID: " CVE-2023-1234 "},
		Package: &Package{Name: "  test-package  ", Version: " 1.2.3 "},
		PrimaryLocation: Location{URI: "  /path/to/file.go  "},
		Artifact: Artifact{Name: "  test-artifact  "},
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		DedupMaterial(f)
	}
}
