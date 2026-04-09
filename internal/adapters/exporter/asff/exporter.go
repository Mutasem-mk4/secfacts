package asff

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	sferr "github.com/secfacts/secfacts/internal/domain/errors"
	"github.com/secfacts/secfacts/internal/domain/evidence"
	"github.com/secfacts/secfacts/internal/ports"
)

const (
	format             = "asff"
	schemaVersion      = "2018-10-08"
	defaultAwsRegion   = "us-east-1"
	productName        = "secfacts"
	opExport           = "asff.Exporter.Export"
	opValidateDocument = "asff.Exporter.validate"
)

type Exporter struct{}

func (Exporter) Format() string {
	return format
}

func (Exporter) Export(ctx context.Context, req ports.ExportRequest) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if req.Writer == nil {
		return sferr.New(sferr.CodeInvalidArgument, opExport, "writer is required")
	}

	config := resolveConfig(req.Options, req.Document)
	if err := validate(config, req.Document); err != nil {
		return err
	}

	iterator := req.Findings
	if iterator == nil {
		iterator = ports.NewSliceFindingIterator(req.Document.Findings)
	}
	defer iterator.Close()

	if req.Options.Pretty {
		findings := make([]finding, 0, len(req.Document.Findings))
		for {
			item, err := iterator.Next(ctx)
			if err == io.EOF {
				break
			}
			if err != nil {
				return sferr.Wrap(sferr.CodeExportFailed, opExport, err, "iterate findings")
			}
			findings = append(findings, mapFinding(config, req.Document, item))
		}

		encoder := json.NewEncoder(req.Writer)
		encoder.SetIndent("", "  ")
		if err := encoder.Encode(findings); err != nil {
			return sferr.Wrap(sferr.CodeExportFailed, opExport, err, "encode ASFF findings")
		}
		return nil
	}

	writer := bufio.NewWriter(req.Writer)
	defer writer.Flush()

	if _, err := writer.WriteString("["); err != nil {
		return sferr.Wrap(sferr.CodeExportFailed, opExport, err, "start ASFF findings")
	}

	first := true
	for {
		item, err := iterator.Next(ctx)
		if err == io.EOF {
			break
		}
		if err != nil {
			return sferr.Wrap(sferr.CodeExportFailed, opExport, err, "iterate findings")
		}

		payload, err := json.Marshal(mapFinding(config, req.Document, item))
		if err != nil {
			return sferr.Wrap(sferr.CodeExportFailed, opExport, err, "marshal ASFF finding")
		}
		if !first {
			if _, err := writer.WriteString(","); err != nil {
				return sferr.Wrap(sferr.CodeExportFailed, opExport, err, "write ASFF delimiter")
			}
		}
		first = false
		if _, err := writer.Write(payload); err != nil {
			return sferr.Wrap(sferr.CodeExportFailed, opExport, err, "write ASFF finding")
		}
	}
	if _, err := writer.WriteString("]\n"); err != nil {
		return sferr.Wrap(sferr.CodeExportFailed, opExport, err, "finalize ASFF findings")
	}

	return nil
}

type config struct {
	awsAccountID string
	awsRegion    string
	productARN   string
	generatorID  string
	productName  string
}

type finding struct {
	SchemaVersion         string                `json:"SchemaVersion"`
	Id                    string                `json:"Id"`
	ProductArn            string                `json:"ProductArn"`
	ProductName           string                `json:"ProductName"`
	AwsAccountId          string                `json:"AwsAccountId"`
	GeneratorId           string                `json:"GeneratorId"`
	Types                 []string              `json:"Types,omitempty"`
	CreatedAt             string                `json:"CreatedAt"`
	UpdatedAt             string                `json:"UpdatedAt"`
	Severity              severity              `json:"Severity"`
	Title                 string                `json:"Title"`
	Description           string                `json:"Description"`
	Resources             []resource            `json:"Resources"`
	FindingProviderFields findingProviderFields `json:"FindingProviderFields,omitempty"`
	ProductFields         map[string]string     `json:"ProductFields,omitempty"`
	Confidence            int                   `json:"Confidence,omitempty"`
}

type severity struct {
	Label      string `json:"Label"`
	Normalized int    `json:"Normalized"`
	Original   string `json:"Original,omitempty"`
}

type resource struct {
	Type               string            `json:"Type"`
	Id                 string            `json:"Id"`
	Partition          string            `json:"Partition,omitempty"`
	Region             string            `json:"Region,omitempty"`
	Details            map[string]any    `json:"Details,omitempty"`
	DataClassification map[string]string `json:"DataClassification,omitempty"`
}

type findingProviderFields struct {
	Severity severity `json:"Severity,omitempty"`
	Types    []string `json:"Types,omitempty"`
}

func resolveConfig(options ports.ExportOptions, document evidence.Document) config {
	accountID := firstNonEmpty(
		options.AWSAccountID,
		os.Getenv("SECFACTS_AWS_ACCOUNT_ID"),
		inferAWSAccountID(document),
	)
	region := firstNonEmpty(
		options.AWSRegion,
		os.Getenv("SECFACTS_AWS_REGION"),
		defaultAwsRegion,
	)
	productARN := firstNonEmpty(
		options.ProductARN,
		os.Getenv("SECFACTS_AWS_PRODUCT_ARN"),
		fmt.Sprintf("arn:aws:securityhub:%s:%s:product/%s/default", region, accountID, accountID),
	)
	generatorID := firstNonEmpty(
		options.GeneratorID,
		os.Getenv("SECFACTS_AWS_GENERATOR_ID"),
		document.Source.ToolName,
		productName,
	)
	product := firstNonEmpty(document.Source.Provider, productName)

	return config{
		awsAccountID: accountID,
		awsRegion:    region,
		productARN:   productARN,
		generatorID:  generatorID,
		productName:  product,
	}
}

func inferAWSAccountID(document evidence.Document) string {
	for _, item := range document.Findings {
		if item.Cloud != nil && strings.TrimSpace(item.Cloud.AccountID) != "" {
			return strings.TrimSpace(item.Cloud.AccountID)
		}
	}

	return ""
}

func validate(cfg config, document evidence.Document) error {
	switch {
	case strings.TrimSpace(document.SchemaVersion) == "":
		return sferr.New(sferr.CodeExportFailed, opValidateDocument, "schema version is required")
	case strings.TrimSpace(cfg.awsAccountID) == "":
		return sferr.New(sferr.CodeExportFailed, opValidateDocument, "AWS account ID is required")
	case strings.TrimSpace(cfg.generatorID) == "":
		return sferr.New(sferr.CodeExportFailed, opValidateDocument, "generator ID is required")
	case strings.TrimSpace(cfg.productARN) == "":
		return sferr.New(sferr.CodeExportFailed, opValidateDocument, "product ARN is required")
	default:
		return nil
	}
}

func mapFinding(cfg config, document evidence.Document, item evidence.Finding) finding {
	createdAt := document.GeneratedAt
	if item.FirstObservedAt != nil {
		createdAt = item.FirstObservedAt.UTC()
	}
	if createdAt.IsZero() {
		createdAt = time.Now().UTC()
	}

	updatedAt := createdAt
	if item.LastObservedAt != nil {
		updatedAt = item.LastObservedAt.UTC()
	}

	id := findingID(item)
	asffSeverity := mapSeverity(item.Severity)
	types := findingTypes(item)

	return finding{
		SchemaVersion: schemaVersion,
		Id:            id,
		ProductArn:    cfg.productARN,
		ProductName:   cfg.productName,
		AwsAccountId:  cfg.awsAccountID,
		GeneratorId:   cfg.generatorID,
		Types:         types,
		CreatedAt:     createdAt.Format(time.RFC3339),
		UpdatedAt:     updatedAt.Format(time.RFC3339),
		Severity:      asffSeverity,
		Title:         firstNonEmpty(item.Title, item.Rule.Name, item.Rule.ID, "security finding"),
		Description:   firstNonEmpty(item.Description, item.Title, "normalized security finding"),
		Resources:     mapResources(cfg, item),
		FindingProviderFields: findingProviderFields{
			Severity: asffSeverity,
			Types:    types,
		},
		ProductFields: map[string]string{
			"secfacts/fingerprint_v1": item.Identity.FingerprintV1.String(),
			"secfacts/dedup_key":      item.Identity.DedupKey.String(),
			"secfacts/natural_key":    item.Identity.NaturalKey.String(),
			"secfacts/kind":           string(item.Kind),
			"secfacts/provider":       item.Source.Provider,
		},
		Confidence: confidenceValue(item.Confidence),
	}
}

func mapSeverity(item evidence.Severity) severity {
	return severity{
		Label:      asffSeverityLabel(item.Label),
		Normalized: normalizeSeverity(item.Score),
		Original:   fmt.Sprintf("%.1f", item.Score),
	}
}

func normalizeSeverity(score float64) int {
	if score <= 0 {
		return 0
	}
	if score >= 10 {
		return 100
	}

	return int(score * 10)
}

func asffSeverityLabel(label evidence.SeverityLabel) string {
	switch label {
	case evidence.SeverityCritical:
		return "CRITICAL"
	case evidence.SeverityHigh:
		return "HIGH"
	case evidence.SeverityMedium:
		return "MEDIUM"
	case evidence.SeverityLow:
		return "LOW"
	default:
		return "INFORMATIONAL"
	}
}

func findingID(item evidence.Finding) string {
	switch {
	case !item.Identity.FingerprintV1.IsZero():
		return "urn:secfacts:finding:" + item.Identity.FingerprintV1.String()
	case strings.TrimSpace(item.ID) != "":
		return "urn:secfacts:finding:" + strings.ToLower(strings.TrimSpace(item.ID))
	default:
		return "urn:secfacts:finding:unknown"
	}
}

func findingTypes(item evidence.Finding) []string {
	switch item.Kind {
	case evidence.KindSCA:
		return []string{"Software and Configuration Checks/Vulnerabilities/CVE"}
	case evidence.KindSAST:
		return []string{"Software and Configuration Checks/Vulnerabilities/Code"}
	case evidence.KindCloud:
		return []string{"Software and Configuration Checks/AWS Security Best Practices"}
	case evidence.KindSecrets:
		return []string{"Sensitive Data Identifications/Secrets"}
	case evidence.KindDAST:
		return []string{"TTPs/Exploitation Attempts"}
	default:
		return []string{"Software and Configuration Checks"}
	}
}

func mapResources(cfg config, item evidence.Finding) []resource {
	resources := make([]resource, 0, 4)

	if item.Cloud != nil {
		resources = append(resources, mapCloudResource(cfg, *item.Cloud))
	}
	if item.Image != nil {
		resources = append(resources, mapImageResource(cfg, *item.Image))
	}
	if item.Package != nil {
		resources = append(resources, mapPackageResource(cfg, *item.Package))
	}
	if item.Artifact.Name != "" || item.PrimaryLocation.URI != "" {
		resources = append(resources, mapArtifactResource(cfg, item))
	}

	if len(resources) == 0 {
		resources = append(resources, resource{
			Type:   "Other",
			Id:     firstNonEmpty(item.PrimaryLocation.URI, item.ID, item.Identity.FingerprintV1.String(), "secfacts:finding"),
			Region: cfg.awsRegion,
		})
	}

	return resources
}

func mapCloudResource(cfg config, cloud evidence.CloudResource) resource {
	resourceType, resourceID := classifyAWSResource(cfg, cloud)

	return resource{
		Type:      resourceType,
		Id:        resourceID,
		Partition: "aws",
		Region:    firstNonEmpty(cloud.Region, cfg.awsRegion),
		Details: map[string]any{
			"Other": map[string]string{
				"Provider":   cloud.Provider,
				"AccountId":  cloud.AccountID,
				"Service":    cloud.Service,
				"ResourceId": cloud.ResourceID,
			},
		},
	}
}

func classifyAWSResource(cfg config, cloud evidence.CloudResource) (string, string) {
	if strings.TrimSpace(cloud.ResourceARN) != "" {
		switch {
		case strings.Contains(cloud.ResourceARN, ":ec2:") && strings.Contains(cloud.ResourceARN, ":instance/"):
			return "AwsEc2Instance", cloud.ResourceARN
		case strings.HasPrefix(cloud.ResourceARN, "arn:aws:s3:::"):
			return "AwsS3Bucket", cloud.ResourceARN
		case strings.Contains(cloud.ResourceARN, ":lambda:") && strings.Contains(cloud.ResourceARN, ":function:"):
			return "AwsLambdaFunction", cloud.ResourceARN
		default:
			return "Other", cloud.ResourceARN
		}
	}

	accountID := firstNonEmpty(cloud.AccountID, cfg.awsAccountID)
	region := firstNonEmpty(cloud.Region, cfg.awsRegion)
	service := strings.ToLower(strings.TrimSpace(cloud.Service))
	resourceID := strings.TrimSpace(cloud.ResourceID)

	switch service {
	case "ec2":
		return "AwsEc2Instance", fmt.Sprintf("arn:aws:ec2:%s:%s:instance/%s", region, accountID, resourceID)
	case "s3":
		return "AwsS3Bucket", fmt.Sprintf("arn:aws:s3:::%s", resourceID)
	case "lambda":
		return "AwsLambdaFunction", fmt.Sprintf("arn:aws:lambda:%s:%s:function:%s", region, accountID, resourceID)
	default:
		return "Other", firstNonEmpty(resourceID, cloud.Service)
	}
}

func mapImageResource(cfg config, image evidence.Image) resource {
	return resource{
		Type:   "Container",
		Id:     firstNonEmpty(image.Digest, image.Repository, image.BaseDigest, "container"),
		Region: cfg.awsRegion,
		Details: map[string]any{
			"Container": map[string]string{
				"ImageId":   firstNonEmpty(image.Digest, image.BaseDigest),
				"ImageName": firstNonEmpty(image.Repository, image.BaseName),
			},
		},
	}
}

func mapPackageResource(cfg config, pkg evidence.Package) resource {
	return resource{
		Type:   "Software and Configuration Checks",
		Id:     firstNonEmpty(pkg.PackageURL, pkg.Name, "package"),
		Region: cfg.awsRegion,
		Details: map[string]any{
			"Other": map[string]string{
				"PackageName":  pkg.Name,
				"PackageURL":   pkg.PackageURL,
				"Version":      pkg.Version,
				"FixedVersion": pkg.FixedVersion,
				"Language":     pkg.Language,
			},
		},
	}
}

func mapArtifactResource(cfg config, item evidence.Finding) resource {
	identifier := firstNonEmpty(item.PrimaryLocation.URI, item.Artifact.Name, "artifact")

	return resource{
		Type:   "Other",
		Id:     identifier,
		Region: cfg.awsRegion,
		Details: map[string]any{
			"Other": map[string]string{
				"ArtifactName": item.Artifact.Name,
				"ArtifactType": item.Artifact.Type,
				"URI":          item.PrimaryLocation.URI,
				"RuleID":       item.Rule.ID,
			},
		},
	}
}

func confidenceValue(confidence evidence.Confidence) int {
	switch confidence {
	case evidence.ConfidenceHigh:
		return 90
	case evidence.ConfidenceMedium:
		return 60
	case evidence.ConfidenceLow:
		return 30
	default:
		return 0
	}
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}

	return ""
}
