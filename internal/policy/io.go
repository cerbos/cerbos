// Copyright 2021-2026 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

//go:build !js && !wasm

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
)

func ReadPolicyFromFile(fsys fs.FS, path string) (*policyv1.Policy, parser.SourceCtx, error) {
	f, err := fsys.Open(path)
	if err != nil {
		return nil, parser.SourceCtx{}, fmt.Errorf("failed to open %s: %w", path, err)
	}
	defer f.Close()

	return ReadPolicy(f)
}

func ReadPolicy(src io.Reader) (*policyv1.Policy, parser.SourceCtx, error) {
	// TODO: Temporary restriction during parser migration to protoyaml.
	return parser.Single(parser.Unmarshal[policyv1.Policy](src))
}

// FindPolicy finds a policy by ID from the given reader.
func FindPolicy(src io.Reader, modID namer.ModuleID) (*policyv1.Policy, parser.SourceCtx, error) {
	return parser.Find(src, func(h *policyv1.Policy) bool { return namer.GenModuleID(h) == modID })
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
