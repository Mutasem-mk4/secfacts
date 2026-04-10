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

type SlackSink struct {
	webhookURL string
	httpClient *http.Client
}

func NewSlackSink() *SlackSink {
	return &SlackSink{
		webhookURL: os.Getenv("AXON_SLACK_WEBHOOK"),
		httpClient: &http.Client{Timeout: 10 * time.Second},
	}
}

func (s *SlackSink) Name() string {
	return "slack"
}

func (s *SlackSink) Emit(ctx context.Context, issue domain.Issue) error {
	if s.webhookURL == "" {
		return nil // Silently skip if not configured
	}

	payload := map[string]interface{}{
		"text": fmt.Sprintf("*Axon: New Security Issue Correlated*\n*ID:* %s\n*Severity:* %.1f (%s)\n*Findings:* %d",
			issue.ID, issue.Severity.Score, issue.Severity.Label, len(issue.Findings)),
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("marshal slack payload: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, "POST", s.webhookURL, bytes.NewBuffer(body))
	if err != nil {
		return fmt.Errorf("create slack request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("send slack notification: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		return fmt.Errorf("slack returned status: %s", resp.Status)
	}

	return nil
}

var _ ports.Sink = (*SlackSink)(nil)
