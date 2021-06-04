// Copyright 2021 Zenauth Ltd.

package policy

import (
	"bytes"
	"io"

	"google.golang.org/protobuf/proto"

	policyv1 "github.com/cerbos/cerbos/internal/genpb/policy/v1"
	"github.com/cerbos/cerbos/internal/util"
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

// WriteGeneratedPolicy writes a generated policy to the destination.
func WriteGeneratedPolicy(dest io.Writer, p *policyv1.GeneratedPolicy) error {
	out, err := proto.Marshal(p)
	if err != nil {
		return err
	}

	_, err = io.Copy(dest, bytes.NewBuffer(out))
	return err
}

func ReadGeneratedPolicy(src io.Reader) (*policyv1.GeneratedPolicy, error) {
	in, err := io.ReadAll(src)
	if err != nil {
		return nil, err
	}

	gp := &policyv1.GeneratedPolicy{}
	if err := proto.Unmarshal(in, gp); err != nil {
		return nil, err
	}

	return gp, nil
}
