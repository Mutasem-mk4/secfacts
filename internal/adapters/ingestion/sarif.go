package ingestion

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"time"

	"github.com/axon/axon/internal/core/domain"
)

// SarifParser implements ports.Parser for SARIF format.
type SarifParser struct{}

func NewSarifParser() *SarifParser {
	return &SarifParser{}
}

func (p *SarifParser) Name() string {
	return "sarif"
}

// Parse implements high-performance SARIF ingestion using streaming JSON decoding.
func (p *SarifParser) Parse(ctx context.Context, r io.Reader) (<-chan domain.Evidence, <-chan error) {
	out := make(chan domain.Evidence)
	errChan := make(chan error, 1)

	go func() {
		defer close(out)
		defer close(errChan)

		decoder := json.NewDecoder(r)

		// Simple streaming: Navigate to 'runs' array
		for decoder.More() {
			token, err := decoder.Token()
			if err != nil {
				if err == io.EOF {
					return
				}
				errChan <- fmt.Errorf("failed to read token: %w", err)
				return
			}

			if token == "runs" {
				if err := p.parseRuns(ctx, decoder, out); err != nil {
					errChan <- err
					return
				}
			}
		}
	}()

	return out, errChan
}

func (p *SarifParser) parseRuns(ctx context.Context, decoder *json.Decoder, out chan<- domain.Evidence) error {
	// Expect start of 'runs' array
	if _, err := decoder.Token(); err != nil {
		return err
	}

	for decoder.More() {
		var run struct {
			Tool struct {
				Driver struct {
					Name string `json:"name"`
				} `json:"driver"`
			} `json:"tool"`
			Results []struct {
				RuleID  string `json:"ruleId"`
				Level   string `json:"level"`
				Message struct {
					Text string `json:"text"`
				} `json:"message"`
				Locations []struct {
					PhysicalLocation struct {
						ArtifactLocation struct {
							URI string `json:"uri"`
						} `json:"artifactLocation"`
						Region struct {
							StartLine int `json:"startLine"`
						} `json:"region"`
					} `json:"physicalLocation"`
				} `json:"locations"`
			} `json:"results"`
		}

		if err := decoder.Decode(&run); err != nil {
			return fmt.Errorf("failed to decode run: %w", err)
		}

		provider := run.Tool.Driver.Name
		for _, res := range run.Results {
			ev := domain.Evidence{
				Provider: provider,
				Type:     p.mapType(res.RuleID),
				Vulnerability: domain.Vulnerability{
					ID:          res.RuleID,
					Description: res.Message.Text,
				},
				Severity:  p.mapSeverity(res.Level),
				Timestamp: time.Now(),
			}

			if len(res.Locations) > 0 {
				loc := res.Locations[0].PhysicalLocation
				ev.Resource = domain.Resource{
					URI:  loc.ArtifactLocation.URI,
					Name: loc.ArtifactLocation.URI,
				}
				ev.Location = &domain.Location{
					Path:      loc.ArtifactLocation.URI,
					StartLine: loc.Region.StartLine,
				}
			}

			select {
			case out <- ev:
			case <-ctx.Done():
				return ctx.Err()
			}
		}
	}

	// Expect end of 'runs' array
	if _, err := decoder.Token(); err != nil {
		return err
	}

	return nil
}

func (p *SarifParser) mapType(ruleID string) domain.FindingType {
	// Heuristic mapping
	return domain.TypeSAST
}

func (p *SarifParser) mapSeverity(level string) domain.Severity {
	var score float32
	switch level {
	case "error":
		score = 9.0
	case "warning":
		score = 5.0
	case "note":
		score = 2.0
	default:
		score = 1.0
	}
	return domain.Severity{Score: score, Label: level}
}
