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

const (
	reset  = "\x1b[0m"
	bold   = "\x1b[1m"
	cyan   = "\x1b[36m"
	yellow = "\x1b[33m"
	green  = "\x1b[32m"
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

	fmt.Printf("\n--- %s%s[AI REMEDIATION PROPOSAL]%s ---\n", bold, cyan, reset)
	fmt.Printf("%sIssue:%s %s\n", bold, reset, issue.ID)
	fmt.Printf("%sExplanation:%s %s\n", bold, reset, proposal.Explanation)
	fmt.Printf("%sRisk Assessment:%s %s\n", bold, reset, proposal.RiskAssessment)
	fmt.Printf("\n%sProposed Fix (Code Diff):%s\n%s\n", bold, reset, proposal.CodeDiff)

	if proposal.CodeDiff == "" {
		fmt.Printf("\n%s[NOTE] No automated fix generated. Please follow the plan manually.%s\n", yellow, reset)
		return nil
	}

	if dryRun {
		fmt.Printf("\n%s[DRY RUN] Skipping application of fix.%s\n", yellow, reset)
		if proposal.CheckCommand != "" {
			fmt.Printf("Suggested verification: %s\n", proposal.CheckCommand)
		}
		return nil
	}

	reader := bufio.NewReader(os.Stdin)
	for {
		fmt.Printf("\n%sDo you want to apply this fix? [y/N]:%s ", bold, reset)
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

	fmt.Printf("%sApplying fix...%s\n", green, reset)
	if err := c.service.ApplyFix(ctx, *proposal); err != nil {
		return fmt.Errorf("failed to apply fix: %w", err)
	}

	return nil
}
