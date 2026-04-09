package evaluate

import (
	"context"

	sferr "github.com/axon/axon/internal/domain/errors"
	"github.com/axon/axon/internal/domain/evidence"
	"github.com/axon/axon/internal/domain/policy"
)

const opRun = "evaluate.Service.Run"

type Engine interface {
	Compare(current []evidence.Finding, baseline []evidence.Finding) policy.BaselineDiff
	Evaluate(ctx context.Context, findings []evidence.Finding, diff policy.BaselineDiff, policy policy.Policy) (policy.Decision, error)
}

type Service struct {
	Engine Engine
}

type Request struct {
	Document evidence.Document
	Baseline evidence.Document
	Policy   policy.Policy
}

func (s Service) Run(ctx context.Context, req Request) (policy.Decision, error) {
	if s.Engine == nil {
		return policy.Decision{}, sferr.New(sferr.CodeInvalidConfig, opRun, "policy engine is required")
	}

	diff := s.Engine.Compare(req.Document.Findings, req.Baseline.Findings)
	decision, err := s.Engine.Evaluate(ctx, req.Document.Findings, diff, req.Policy)
	if err != nil {
		return policy.Decision{}, sferr.Wrap(sferr.CodePolicyFailed, opRun, err, "evaluate policy")
	}

	return decision, nil
}
