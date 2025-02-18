// Copyright 2021-2025 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package policy

import (
	"bytes"
	"fmt"
	"io"
	"io/fs"

	policyv1 "github.com/cerbos/cerbos/api/genpb/cerbos/policy/v1"
	"github.com/cerbos/cerbos/internal/namer"
	"github.com/cerbos/cerbos/internal/parser"
	"github.com/cerbos/cerbos/internal/util"
	"github.com/cerbos/cerbos/internal/validator"
)

func ReadPolicyFromFile(fsys fs.FS, path string) (*policyv1.Policy, error) {
	f, err := fsys.Open(path)
	if err != nil {
		return nil, fmt.Errorf("failed to open %s: %w", path, err)
	}
	defer f.Close()

	return ReadPolicy(f)
}

// ReadPolicy reads a policy from the given reader.
func ReadPolicy(src io.Reader) (*policyv1.Policy, error) {
	p := &policyv1.Policy{}
	if err := util.ReadJSONOrYAML(src, p); err != nil {
		return nil, err
	}

	return p, nil
}

// ReadPolicyWithSourceContext reads a policy and returns it along with information about its source.
func ReadPolicyWithSourceContext(fsys fs.FS, path string) (*policyv1.Policy, parser.SourceCtx, error) {
	f, err := fsys.Open(path)
	if err != nil {
		return nil, parser.SourceCtx{}, fmt.Errorf("failed to open %s: %w", path, err)
	}
	defer f.Close()

	return ReadPolicyWithSourceContextFromReader(f)
}

func ReadPolicyWithSourceContextFromReader(src io.Reader) (*policyv1.Policy, parser.SourceCtx, error) {
	policies, contexts, err := parser.Unmarshal(src, func() *policyv1.Policy { return &policyv1.Policy{} }, parser.WithValidator(validator.Validator()))
	switch len(policies) {
	case 0:
		return nil, parser.SourceCtx{}, err
	case 1:
		return policies[0], contexts[0], err
	default:
		// TODO: Temporary restriction during parser migration to protoyaml.
		return nil, parser.SourceCtx{}, util.ErrMultipleYAMLDocs
	}
}

// FindPolicy finds a policy by ID from the given reader.
func FindPolicy(src io.Reader, modID namer.ModuleID) (*policyv1.Policy, parser.SourceCtx, error) {
	p := &policyv1.Policy{}
	sc, err := parser.Find(src, func(h *policyv1.Policy) bool { return namer.GenModuleID(h) == modID }, p)
	return p, sc, err
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
