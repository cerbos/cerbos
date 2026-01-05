// Copyright 2021-2026 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package test

import (
	"bytes"
	"fmt"
	"io/fs"
	"maps"
	"path/filepath"
	"testing"
	"text/template"

	sprig "github.com/Masterminds/sprig/v3"
	"google.golang.org/protobuf/encoding/protojson"

	policyv1 "github.com/cerbos/cerbos/api/genpb/cerbos/policy/v1"
	"github.com/cerbos/cerbos/internal/policy"
)

func RenderTemplate(tb testing.TB, path string, data any) []byte {
	tb.Helper()

	tmpl, err := template.New(filepath.Base(path)).Funcs(TemplateFuncs()).ParseFiles(path)
	if err != nil {
		tb.Fatalf("Failed to parse template from %q: %v", path, err)
	}

	output := new(bytes.Buffer)
	if err := tmpl.Execute(output, data); err != nil {
		tb.Fatalf("Failed to execute template at %q: %v", path, err)
	}

	return output.Bytes()
}

func TemplateFuncs() template.FuncMap {
	funcs := make(map[string]any)
	maps.Copy(funcs, sprig.FuncMap())

	th := &templateHelper{fsys: DataFS()}
	funcs["fileBytes"] = th.FileBytes
	funcs["fileString"] = th.FileString
	funcs["readPolicy"] = th.ReadPolicy
	funcs["toPolicyJSON"] = th.ToPolicyJSON

	return template.FuncMap(funcs)
}

type templateHelper struct {
	fsys fs.FS
}

func (th *templateHelper) FileBytes(relPath string) []byte {
	b, err := fs.ReadFile(th.fsys, relPath)
	if err != nil {
		panic(fmt.Errorf("failed to read file %q: %w", relPath, err))
	}
	return b
}

func (th *templateHelper) FileString(relPath string) string {
	return string(th.FileBytes(relPath))
}

func (th *templateHelper) ToPolicyJSON(p *policyv1.Policy) string {
	return protojson.Format(p)
}

func (th *templateHelper) ReadPolicy(relPath string) *policyv1.Policy {
	p, err := policy.ReadPolicyFromFile(th.fsys, relPath)
	if err != nil {
		panic(fmt.Errorf("failed to read policy from %q: %w", relPath, err))
	}

	return p
}
