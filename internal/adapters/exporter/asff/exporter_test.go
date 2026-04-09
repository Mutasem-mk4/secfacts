package asff

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/axon/axon/internal/domain/evidence"
	"github.com/axon/axon/internal/ports"
)

func TestExporterGolden(t *testing.T) {
	t.Parallel()

	observedAt := time.Date(2026, 4, 9, 10, 0, 0, 0, time.UTC)
	document := evidence.Document{
		SchemaVersion: evidence.SchemaVersion,
		GeneratedAt:   observedAt,
		Source: evidence.SourceDescriptor{
			Provider:    "axon",
			ToolName:    "axon",
			ToolVersion: "0.1.0-test",
		},
		Findings: []evidence.Finding{
			{
				ID:    "sca-1",
				Kind:  evidence.KindSCA,
				Title: "openssl vulnerable package",
				Severity: evidence.Severity{
					Score: 8.2,
					Label: evidence.SeverityHigh,
				},
				Rule: evidence.Rule{
					ID:   "CVE-2024-0001",
					Name: "OpenSSL vulnerability",
				},
				Package: &evidence.Package{
					Name:         "openssl",
					Version:      "1.0.2",
					FixedVersion: "1.0.3",
					PackageURL:   "pkg:apk/alpine/openssl@1.0.2",
				},
				Vulnerability: &evidence.Vulnerability{
					ID: "CVE-2024-0001",
				},
				Identity: evidence.Identity{
					FingerprintV1: testHash('a'),
					DedupKey:      testHash('b'),
					NaturalKey:    testHash('c'),
				},
				FirstObservedAt: &observedAt,
				LastObservedAt:  &observedAt,
			},
			{
				ID:    "sast-1",
				Kind:  evidence.KindSAST,
				Title: "tainted input reaches sink",
				Severity: evidence.Severity{
					Score: 5.0,
					Label: evidence.SeverityMedium,
				},
				Rule: evidence.Rule{
					ID:   "go.sql.injection",
					Name: "SQL injection",
				},
				PrimaryLocation: evidence.Location{
					URI:  "internal/repository/user.go",
					Line: 44,
				},
				Artifact: evidence.Artifact{
					Name: "internal/repository/user.go",
					Type: "file",
				},
				Identity: evidence.Identity{
					FingerprintV1: testHash('d'),
					DedupKey:      testHash('e'),
					NaturalKey:    testHash('f'),
				},
				FirstObservedAt: &observedAt,
				LastObservedAt:  &observedAt,
			},
		},
	}

	var buffer bytes.Buffer
	err := Exporter{}.Export(context.Background(), ports.ExportRequest{
		Document: document,
		Writer:   &buffer,
		Options: ports.ExportOptions{
			Pretty:       true,
			AWSAccountID: "123456789012",
			AWSRegion:    "us-east-1",
			ProductARN:   "arn:aws:securityhub:us-east-1:123456789012:product/123456789012/default",
			GeneratorID:  "axon/test",
		},
	})
	if err != nil {
		t.Fatalf("Export returned error: %v", err)
	}

	goldenPath := filepath.Join("testdata", "golden_asff.json")
	expected, err := os.ReadFile(goldenPath)
	if err != nil {
		t.Fatalf("ReadFile returned error: %v", err)
	}

	got := strings.TrimSpace(strings.ReplaceAll(buffer.String(), "\r\n", "\n"))
	want := strings.TrimSpace(strings.ReplaceAll(string(expected), "\r\n", "\n"))
	if got != want {
		t.Fatalf("golden mismatch\nexpected:\n%s\ngot:\n%s", want, got)
	}
}

func TestMapCloudResourceRefinesAWSResourceTypes(t *testing.T) {
	t.Parallel()

	cfg := config{
		awsAccountID: "123456789012",
		awsRegion:    "us-east-1",
	}

	ec2 := mapCloudResource(cfg, evidence.CloudResource{
		Provider:   "aws",
		AccountID:  "123456789012",
		Region:     "us-east-1",
		Service:    "ec2",
		ResourceID: "i-0123456789abcdef0",
	})
	if ec2.Type != "AwsEc2Instance" {
		t.Fatalf("expected AwsEc2Instance, got %s", ec2.Type)
	}
	if ec2.Id != "arn:aws:ec2:us-east-1:123456789012:instance/i-0123456789abcdef0" {
		t.Fatalf("unexpected ec2 ARN: %s", ec2.Id)
	}

	s3 := mapCloudResource(cfg, evidence.CloudResource{
		Provider:   "aws",
		AccountID:  "123456789012",
		Region:     "us-east-1",
		Service:    "s3",
		ResourceID: "my-bucket",
	})
	if s3.Type != "AwsS3Bucket" {
		t.Fatalf("expected AwsS3Bucket, got %s", s3.Type)
	}
	if s3.Id != "arn:aws:s3:::my-bucket" {
		t.Fatalf("unexpected s3 ARN: %s", s3.Id)
	}

	lambda := mapCloudResource(cfg, evidence.CloudResource{
		Provider:   "aws",
		AccountID:  "123456789012",
		Region:     "us-east-1",
		Service:    "lambda",
		ResourceID: "my-function",
	})
	if lambda.Type != "AwsLambdaFunction" {
		t.Fatalf("expected AwsLambdaFunction, got %s", lambda.Type)
	}
	if lambda.Id != "arn:aws:lambda:us-east-1:123456789012:function:my-function" {
		t.Fatalf("unexpected lambda ARN: %s", lambda.Id)
	}
}

func testHash(ch byte) evidence.Hash {
	hash, ok := evidence.ParseHash(strings.Repeat(string([]byte{ch}), 64))
	if !ok {
		panic("invalid test hash")
	}

	return hash
}
