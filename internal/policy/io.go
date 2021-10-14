// Copyright 2021 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package policy

import (
	"bytes"
	"io"

	policyv1 "github.com/cerbos/cerbos/api/genpb/cerbos/policy/v1"
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

// WriteBinaryPolicy writes a policy as binary (protobuf encoding).
func WriteBinaryPolicy(dest io.Writer, p *policyv1.Policy) error {
	out, err := p.MarshalVT()
	if err != nil {
		return err
	}

	var buf [128]byte
	_, err = io.CopyBuffer(dest, bytes.NewBuffer(out), buf[:])
	return err
}

// ReadBinaryPolicy reads a policy from binary (protobuf encoding).
func ReadBinaryPolicy(src io.Reader) (*policyv1.Policy, error) {
	in, err := io.ReadAll(src)
	if err != nil {
		return nil, err
	}

	p := &policyv1.Policy{}
	if err := p.UnmarshalVT(in); err != nil {
		return nil, err
	}

	return p, nil
}
