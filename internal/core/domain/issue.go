package domain

// Issue represents a correlated security concern grouped by resource.
// It uses pointers to original Evidence to maintain a low-allocation footprint.
type Issue struct {
	ID          string               `json:"id"`
	Type        string               `json:"type"`
	Target      Resource             `json:"target"`
	Severity    Severity             `json:"severity"`
	Remediation string               `json:"remediation"` // Static or tool-suggested fix
	AIProposal  *RemediationProposal `json:"ai_proposal,omitempty"`
	Findings    []*Evidence          `json:"findings"`
}

// RemediationProposal defines the structured AI-assisted fix.
type RemediationProposal struct {
	Explanation    string `json:"explanation"`    // Why this fix is needed
	RiskAssessment string `json:"risk_assessment"` // Potential side effects
	Plan           string `json:"plan"`            // Step-by-step instructions
	CodeDiff       string `json:"code_diff"`       // Unified Diff format
	CheckCommand   string `json:"check_command"`   // Command to verify fix
}

// IssueAggregator defines the result of the correlation process.
type IssueAggregator struct {
	Issues []*Issue `json:"issues"`
}
