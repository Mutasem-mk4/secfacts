package baseline

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/axon/axon/internal/adapters/parser/iemjson"
)

func TestLoadIEMJSONReadsExportedDocument(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	path := filepath.Join(dir, "baseline.json")
	data := `{
  "SchemaVersion":"axon.iem/v1alpha1",
  "Findings":[
    {
      "ID":"finding-1",
      "Kind":"sca",
      "Identity":{"FingerprintV1":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}
    }
  ]
}`
	if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
		t.Fatalf("WriteFile returned error: %v", err)
	}

	document, err := LoadIEMJSON(context.Background(), path, iemjson.Parser{})
	if err != nil {
		t.Fatalf("LoadIEMJSON returned error: %v", err)
	}
	if len(document.Findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(document.Findings))
	}
	if document.Findings[0].Identity.FingerprintV1.String() != "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" {
		t.Fatalf("unexpected fingerprint: %#v", document.Findings[0].Identity)
	}
}
