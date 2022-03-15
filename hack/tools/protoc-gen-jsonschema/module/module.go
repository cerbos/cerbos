// Copyright 2021-2022 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package module

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/cerbos/cerbos/hack/tools/protoc-gen-jsonschema/jsonschema"
	pgs "github.com/lyft/protoc-gen-star"
)

type Module struct {
	*pgs.ModuleBase
	nestedUnderMessage pgs.Message
	definitions        map[string]jsonschema.Schema
}

func New() pgs.Module {
	return &Module{ModuleBase: &pgs.ModuleBase{}}
}

func (*Module) Name() string {
	return "jsonschema"
}

func (m *Module) Execute(targets map[string]pgs.File, pkgs map[string]pgs.Package) []pgs.Artifact {
	for _, file := range targets {
		m.Push(fmt.Sprintf("file:%s", file.Name()))

		for _, message := range file.Messages() {
			filename := m.filename(message)

			schema := m.defineMessage(message)
			schema.TopLevel("https://api.cerbos.dev/" + filename)

			content, err := json.MarshalIndent(schema, "", "  ")
			m.CheckErr(err, "failed to marshal JSON schema")

			m.AddGeneratorFile(filename, string(content)+"\n")
		}

		m.Pop()
	}

	return m.Artifacts()
}

func (*Module) filename(message pgs.Message) string {
	name := message.FullyQualifiedName()
	name = strings.TrimPrefix(name, ".")
	name = strings.ReplaceAll(name, ".", "/")
	return name + ".schema.json"
}
