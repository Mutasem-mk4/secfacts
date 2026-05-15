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
	colorReset  = "\x1b[0m"
	colorRed    = "\x1b[31m"
	colorGreen  = "\x1b[32m"
	colorYellow = "\x1b[33m"
	colorBlue   = "\x1b[34m"
	colorCyan   = "\x1b[36m"
	colorBold   = "\x1b[1m"
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

	fmt.Printf("\n%s%s--- [AI REMEDIATION PROPOSAL] ---%s\n", colorBold, colorCyan, colorReset)
	fmt.Printf("%sIssue:%s %s\n", colorBold, colorReset, issue.ID)
	fmt.Printf("%sExplanation:%s %s\n", colorBold, colorReset, proposal.Explanation)
	fmt.Printf("%sRisk Assessment:%s %s\n", colorBold, colorReset, proposal.RiskAssessment)
	fmt.Printf("\n%sProposed Fix (Code Diff):%s\n%s%s%s\n", colorBold, colorReset, colorGreen, proposal.CodeDiff, colorReset)

	if proposal.CodeDiff == "" {
		fmt.Printf("\n%s📝 [NOTE]%s No automated fix generated. Please follow the plan manually.\n", colorYellow, colorReset)
		return nil
	}

	if dryRun {
		fmt.Printf("\n%s🏃 [DRY RUN]%s Skipping application of fix.\n", colorYellow, colorReset)
		if proposal.CheckCommand != "" {
			fmt.Printf("%sSuggested verification:%s %s\n", colorBold, colorReset, proposal.CheckCommand)
		}
		return nil
	}

	reader := bufio.NewReader(os.Stdin)
	for {
		fmt.Printf("\n%s❓ Do you want to apply this fix? [y/N]:%s ", colorBold, colorReset)
		response, err := reader.ReadString('\n')
		if err != nil {
			return fmt.Errorf("read response: %w", err)
		}
		response = strings.ToLower(strings.TrimSpace(response))

		if response == "" || response == "n" || response == "no" {
			fmt.Printf("%s❌ Remediation aborted by user.%s\n", colorRed, colorReset)
			return nil
		}
		if response == "y" || response == "yes" {
			break
		}
		fmt.Printf("%s⚠️ Invalid input. Please type 'y' to continue or 'n' to abort.%s\n", colorYellow, colorReset)
	}

	fmt.Printf("%s⏳ Applying fix...%s\n", colorBlue, colorReset)
	if err := c.service.ApplyFix(ctx, *proposal); err != nil {
		return fmt.Errorf("failed to apply fix: %w", err)
	}

	fmt.Printf("%s✅ Fix applied successfully.%s\n", colorGreen, colorReset)
	return nil
}
