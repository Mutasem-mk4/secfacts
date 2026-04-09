package openai

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"

	"github.com/cenkalti/backoff/v4"
	"github.com/secfacts/secfacts/internal/core/domain"
	"github.com/secfacts/secfacts/internal/core/services/ai/prompt"
	"github.com/secfacts/secfacts/internal/core/services/ai/utils"
)

const (
	defaultModel = "gpt-4o"
	apiURL       = "https://api.openai.com/v1/chat/completions"
)

// OpenAIAdapter implements the RemediationProvider for OpenAI.
type OpenAIAdapter struct {
	apiKey         string
	organizationID string
	model          string
	client         *http.Client
}

// NewOpenAIAdapter creates a new adapter from environment variables.
func NewOpenAIAdapter(model string) (*OpenAIAdapter, error) {
	apiKey := os.Getenv("OPENAI_API_KEY")
	if apiKey == "" {
		return nil, fmt.Errorf("OPENAI_API_KEY environment variable not set")
	}

	if model == "" {
		model = defaultModel
	}

	return &OpenAIAdapter{
		apiKey:         apiKey,
		organizationID: os.Getenv("OPENAI_ORG_ID"),
		model:          model,
		client:         &http.Client{Timeout: 60 * time.Second},
	}, nil
}

func (a *OpenAIAdapter) Name() string {
	return "openai"
}

// SuggestFix requests a remediation proposal from OpenAI with exponential backoff.
func (a *OpenAIAdapter) SuggestFix(ctx context.Context, issue domain.Issue) (*domain.RemediationProposal, error) {
	findings := ""
	for _, f := range issue.Findings {
		findings += fmt.Sprintf("- %s: %s\n", f.Provider, f.Vulnerability.Description)
	}
	userPrompt := prompt.GenerateUserPrompt(issue.ID, issue.Target.URI, findings)

	requestBody := map[string]interface{}{
		"model": a.model,
		"messages": []map[string]string{
			{"role": "system", "content": prompt.SystemPrompt},
			{"role": "user", "content": userPrompt},
		},
		"response_format": map[string]string{"type": "json_object"},
	}

	jsonData, err := json.Marshal(requestBody)
	if err != nil {
		return nil, err
	}

	var proposal *domain.RemediationProposal
	operation := func() error {
		req, err := http.NewRequestWithContext(ctx, "POST", apiURL, bytes.NewBuffer(jsonData))
		if err != nil {
			return err
		}

		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+a.apiKey)
		if a.organizationID != "" {
			req.Header.Set("OpenAI-Organization", a.organizationID)
		}

		resp, err := a.client.Do(req)
		if err != nil {
			return err
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			body, _ := io.ReadAll(resp.Body)
			if resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode >= 500 {
				return fmt.Errorf("openai error (%d): %s", resp.StatusCode, string(body))
			}
			return backoff.Permanent(fmt.Errorf("openai permanent error (%d): %s", resp.StatusCode, string(body)))
		}

		var res struct {
			Choices []struct {
				Message struct {
					Content string `json:"content"`
				} `json:"message"`
			} `json:"choices"`
		}

		if err := json.NewDecoder(resp.Body).Decode(&res); err != nil {
			return err
		}

		if len(res.Choices) == 0 {
			return fmt.Errorf("no choices returned from OpenAI")
		}

		proposal, err = aiutils.ExtractJSON(res.Choices[0].Message.Content)
		return err
	}

	bo := backoff.NewExponentialBackOff()
	bo.MaxElapsedTime = 2 * time.Minute
	err = backoff.Retry(operation, backoff.WithContext(bo, ctx))
	if err != nil {
		return nil, err
	}

	return proposal, nil
}
