package sink

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/axon/axon/internal/core/domain"
	"github.com/axon/axon/internal/core/ports"
)

type JiraSink struct {
	baseURL    string
	username   string
	apiToken   string
	projectKey string
	httpClient *http.Client
}

func NewJiraSink() *JiraSink {
	return &JiraSink{
		baseURL:    os.Getenv("AXON_JIRA_URL"),
		username:   os.Getenv("AXON_JIRA_USER"),
		apiToken:   os.Getenv("AXON_JIRA_TOKEN"),
		projectKey: os.Getenv("AXON_JIRA_PROJECT"),
		httpClient: &http.Client{Timeout: 10 * time.Second},
	}
}

func (s *JiraSink) Name() string {
	return "jira"
}

func (s *JiraSink) Emit(ctx context.Context, issue domain.Issue) error {
	if s.baseURL == "" || s.apiToken == "" || s.projectKey == "" {
		return nil // Silently skip if not configured
	}

	summary := fmt.Sprintf("[Axon] %s Security Issue", issue.Severity.Label)
	description := fmt.Sprintf("Axon correlated security issue identified.\nID: %s\nFindings: %d\nScore: %.1f",
		issue.ID, len(issue.Findings), issue.Severity.Score)

	payload := map[string]interface{}{
		"fields": map[string]interface{}{
			"project": map[string]string{
				"key": s.projectKey,
			},
			"summary":     summary,
			"description": description,
			"issuetype": map[string]string{
				"name": "Bug",
			},
		},
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("marshal jira payload: %w", err)
	}

	url := fmt.Sprintf("%s/rest/api/2/issue", s.baseURL)
	req, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewBuffer(body))
	if err != nil {
		return fmt.Errorf("create jira request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.SetBasicAuth(s.username, s.apiToken)

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("create jira issue: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		return fmt.Errorf("jira returned status: %s", resp.Status)
	}

	return nil
}

var _ ports.Sink = (*JiraSink)(nil)
