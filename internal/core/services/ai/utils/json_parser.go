package aiutils

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strings"

	"github.com/secfacts/secfacts/internal/core/domain"
)

// ExtractJSON handles potentially "messy" output from LLMs by finding the first JSON block.
func ExtractJSON(input string) (*domain.RemediationProposal, error) {
	// Regular expression to find JSON blocks
	re := regexp.MustCompile(`(?s)\{.*\}`)
	match := re.FindString(input)
	if match == "" {
		return nil, fmt.Errorf("no JSON block found in AI output")
	}

	// Clean up common markdown formatting if present
	match = strings.TrimPrefix(match, "```json")
	match = strings.TrimSuffix(match, "```")
	match = strings.TrimSpace(match)

	var proposal domain.RemediationProposal
	if err := json.Unmarshal([]byte(match), &proposal); err != nil {
		return nil, fmt.Errorf("failed to unmarshal JSON proposal: %w", err)
	}

	return &proposal, nil
}
