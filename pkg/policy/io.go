package policy

import (
	"io"

	policyv1 "github.com/charithe/menshen/pkg/generated/policy/v1"
	"github.com/charithe/menshen/pkg/util"
)

// ReadPolicy reads a policy from the given reader.
func ReadPolicy(src io.Reader) (*policyv1.Policy, error) {
	policy := &policyv1.Policy{}
	if err := util.ReadJSONOrYAML(src, policy); err != nil {
		return nil, err
	}

	return policy, nil
}

// WritePolicy writes a policy as YAML to the destination.
func WritePolicy(dest io.Writer, p *policyv1.Policy) error {
	return util.WriteYAML(dest, p)
}
