// Copyright 2021-2024 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package templates

import (
	"embed"
	"encoding/json"
	"fmt"
	"text/template"
)

func parse(fsys embed.FS) *template.Template {
	return template.Must(template.ParseFS(fsys, "*/*"))
}

var (
	//go:embed binary
	binaryPackageFiles embed.FS

	//go:embed wrapper
	wrapperPackageFiles embed.FS

	BinaryPackage  = parse(binaryPackageFiles)
	WrapperPackage = parse(wrapperPackageFiles)
)

type Platform struct {
	OS   string
	Arch string
}

func (p Platform) String() string {
	return fmt.Sprintf("%s-%s", p.OS, p.Arch)
}

type BinaryPackageData struct {
	Platform
	Name    string
	Binary  string
	Version string
}

type WrapperPackageData struct {
	Name      string
	Version   string
	Platforms []Platform
}

func (w WrapperPackageData) OptionalDependencies() (string, error) {
	optionalDependencies := make(map[string]string, len(w.Platforms))

	for _, platform := range w.Platforms {
		optionalDependencies[fmt.Sprintf("@cerbos/%s-%s", w.Name, platform)] = w.Version
	}

	return toJSON(optionalDependencies, "  ")
}

func (w WrapperPackageData) SupportedPlatforms() (string, error) {
	supportedPlatforms := make([]string, len(w.Platforms))

	for i, platform := range w.Platforms {
		supportedPlatforms[i] = platform.String()
	}

	return toJSON(supportedPlatforms, "")
}

func toJSON(value any, prefix string) (string, error) {
	result, err := json.MarshalIndent(value, prefix, "  ")
	return string(result), err
}
