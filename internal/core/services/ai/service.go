package ai

import (
	"context"
	"fmt"
	"os"
	"os/exec"

	"github.com/axon/axon/internal/core/domain"
	"github.com/axon/axon/internal/core/ports"
	"github.com/rs/zerolog/log"
)

// Service coordinates the AI-assisted remediation lifecycle.
type Service struct {
	provider ports.RemediationProvider
}

// NewService creates a new remediation service with the given LLM provider.
func NewService(provider ports.RemediationProvider) *Service {
	return &Service{provider: provider}
}

// AnalyzeIssue gathers context and requests a fix proposal from the AI provider.
func (s *Service) AnalyzeIssue(ctx context.Context, issue domain.Issue) (*domain.RemediationProposal, error) {
	log.Debug().Str("issue_id", issue.ID).Msg("analyzing issue for remediation")

	// 1. Gather Minimal Context (Zero-Copy Philosophy)
	// We only extract what's necessary to point the AI to the problem.
	// In a real implementation, we might read the specific line from the file if available.

	// 2. Delegate to Provider
	proposal, err := s.provider.SuggestFix(ctx, issue)
	if err != nil {
		return nil, fmt.Errorf("ai provider error: %w", err)
	}

	return proposal, nil
}

// ApplyFix applies the suggested diff to the filesystem.
func (s *Service) ApplyFix(ctx context.Context, proposal domain.RemediationProposal) error {
	if proposal.CodeDiff == "" {
		return fmt.Errorf("no code diff provided in proposal")
	}

	// For safety, we use 'patch' command if available, or write a temporary file.
	// This implementation assumes a standard Unix-like environment or 'git apply'.

	tmpFile, err := os.CreateTemp("", "axon-fix-*.patch")
	if err != nil {
		return fmt.Errorf("create temp patch: %w", err)
	}
	defer os.Remove(tmpFile.Name())

	if _, err := tmpFile.WriteString(proposal.CodeDiff); err != nil {
		return fmt.Errorf("write patch: %w", err)
	}
	tmpFile.Close()

	// Use 'git apply' as it's often more robust for unified diffs.
	cmd := exec.CommandContext(ctx, "git", "apply", tmpFile.Name())
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("apply patch failed: %s: %w", string(output), err)
	}

	log.Info().Msg("remediation fix applied successfully")

	if proposal.CheckCommand != "" {
		fmt.Printf("\n[Verification Needed] Run the following to confirm the fix:\n  %s\n", proposal.CheckCommand)
	}

	return nil
}

var _ ports.RemediationService = (*Service)(nil)
