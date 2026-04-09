package ollama

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/cenkalti/backoff/v4"
	"github.com/secfacts/secfacts/internal/core/domain"
	"github.com/secfacts/secfacts/internal/core/services/ai/prompt"
	"github.com/secfacts/secfacts/internal/core/services/ai/utils"
)

const (
	defaultModel = "llama3"
	defaultURL   = "http://localhost:11434/api/chat"
)

// OllamaAdapter implements the RemediationProvider for Ollama.
type OllamaAdapter struct {
	url    string
	model  string
	client *http.Client
}

// NewOllamaAdapter creates a new Ollama adapter.
func NewOllamaAdapter(url, model string) *OllamaAdapter {
	if url == "" {
		url = defaultURL
	}
	if model == "" {
		model = defaultModel
	}

	return &OllamaAdapter{
		url:    url,
		model:  model,
		client: &http.Client{Timeout: 5 * time.Minute}, // Local models can be slow
	}
}

func (a *OllamaAdapter) Name() string {
	return "ollama"
}

// SuggestFix requests a remediation proposal from Ollama with exponential backoff.
func (a *OllamaAdapter) SuggestFix(ctx context.Context, issue domain.Issue) (*domain.RemediationProposal, error) {
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
		"stream": false,
		"format": "json",
	}

	jsonData, err := json.Marshal(requestBody)
	if err != nil {
		return nil, err
	}

	var proposal *domain.RemediationProposal
	operation := func() error {
		req, err := http.NewRequestWithContext(ctx, "POST", a.url, bytes.NewBuffer(jsonData))
		if err != nil {
			return err
		}

		req.Header.Set("Content-Type", "application/json")

		resp, err := a.client.Do(req)
		if err != nil {
			return err
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			body, _ := io.ReadAll(resp.Body)
			if resp.StatusCode >= 500 {
				return fmt.Errorf("ollama error (%d): %s", resp.StatusCode, string(body))
			}
			return backoff.Permanent(fmt.Errorf("ollama permanent error (%d): %s", resp.StatusCode, string(body)))
		}

		var res struct {
			Message struct {
				Content string `json:"content"`
			} `json:"message"`
		}

		if err := json.NewDecoder(resp.Body).Decode(&res); err != nil {
			return err
		}

		proposal, err = aiutils.ExtractJSON(res.Message.Content)
		return err
	}

	bo := backoff.NewExponentialBackOff()
	bo.MaxElapsedTime = 10 * time.Minute
	err = backoff.Retry(operation, backoff.WithContext(bo, ctx))
	if err != nil {
		return nil, err
	}

	return proposal, nil
}
