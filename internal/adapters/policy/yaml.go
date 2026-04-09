package policy

import (
	"os"

	"gopkg.in/yaml.v3"

	sferr "github.com/axon/axon/internal/domain/errors"
	domainpolicy "github.com/axon/axon/internal/domain/policy"
)

const opLoad = "policyyaml.LoadFile"

func LoadFile(path string) (domainpolicy.Policy, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return domainpolicy.Policy{}, sferr.Wrap(sferr.CodeIO, opLoad, err, "read policy file")
	}

	var policy domainpolicy.Policy
	if err := yaml.Unmarshal(data, &policy); err != nil {
		return domainpolicy.Policy{}, sferr.Wrap(sferr.CodePolicyFailed, opLoad, err, "decode policy yaml")
	}

	return policy, nil
}
