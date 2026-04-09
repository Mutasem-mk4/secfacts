package cli

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/axon/axon/internal/core/domain"
	"github.com/axon/axon/internal/core/ports"
)

// RemediationCLI handles the interactive review and apply flow.
type RemediationCLI struct {
	service ports.RemediationService
}

// NewRemediationCLI creates a new interactive remediation handler.
func NewRemediationCLI(service ports.RemediationService) *RemediationCLI {
	return &RemediationCLI{service: service}
}

// ReviewAndApply presents the proposal to the user and asks for confirmation.
func (c *RemediationCLI) ReviewAndApply(ctx context.Context, issue domain.Issue, dryRun bool) error {
	proposal, err := c.service.AnalyzeIssue(ctx, issue)
	if err != nil {
		return fmt.Errorf("analysis failed: %w", err)
	}

	fmt.Printf("\n--- [AI REMEDIATION PROPOSAL] ---\n")
	fmt.Printf("Issue: %s\n", issue.ID)
	fmt.Printf("Explanation: %s\n", proposal.Explanation)
	fmt.Printf("Risk Assessment: %s\n", proposal.RiskAssessment)
	fmt.Printf("\nProposed Fix (Code Diff):\n%s\n", proposal.CodeDiff)

	if proposal.CodeDiff == "" {
		fmt.Printf("\n[NOTE] No automated fix generated. Please follow the plan manually.\n")
		return nil
	}

	if dryRun {
		fmt.Printf("\n[DRY RUN] Skipping application of fix.\n")
		if proposal.CheckCommand != "" {
			fmt.Printf("Suggested verification: %s\n", proposal.CheckCommand)
		}
		return nil
	}

	reader := bufio.NewReader(os.Stdin)
	for {
		fmt.Printf("\nDo you want to apply this fix? [y/N]: ")
		response, err := reader.ReadString('\n')
		if err != nil {
			return fmt.Errorf("read response: %w", err)
		}
		response = strings.ToLower(strings.TrimSpace(response))

		if response == "" || response == "n" || response == "no" {
			fmt.Println("Remediation aborted by user.")
			return nil
		}
		if response == "y" || response == "yes" {
			break
		}
		fmt.Println("Invalid input. Please type 'y' to continue or 'n' to abort.")
	}

	fmt.Println("Applying fix...")
	if err := c.service.ApplyFix(ctx, *proposal); err != nil {
		return fmt.Errorf("failed to apply fix: %w", err)
	}

	return nil
}
