// Copyright 2021-2026 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"text/template"

	"github.com/cerbos/cerbos/hack/tools/generate-npm-packages/templates"
	"go.uber.org/multierr"
	"gopkg.in/yaml.v3"
)

var (
	binaries = []string{
		"cerbos",
		"cerbosctl",
	}

	platforms = []templates.Platform{
		{OS: "darwin", Arch: "arm64"},
		{OS: "darwin", Arch: "x64"},
		{OS: "linux", Arch: "arm64"},
		{OS: "linux", Arch: "x64"},
	}
)

const (
	antoraConfigFile = "docs/antora.yml"
	outDir           = "npm/packages"
	dirPerm          = 0o755
)

type AntoraConfig struct {
	Version    string
	Prerelease string
}

func main() {
	err := generatePackages()
	if err != nil {
		log.Fatalln(err)
	}
}

func generatePackages() error {
	version, err := readVersion()
	if err != nil {
		return err
	}

	err = os.RemoveAll(outDir)
	if err != nil {
		return fmt.Errorf("failed to remove output directory %q: %w", outDir, err)
	}

	err = os.Mkdir(outDir, dirPerm)
	if err != nil {
		return fmt.Errorf("failed to create output directory %q: %w", outDir, err)
	}

	for _, binary := range binaries {
		err := generatePackage(binary, templates.WrapperPackage, templates.WrapperPackageData{
			Name:      binary,
			Version:   version,
			Platforms: platforms,
		})
		if err != nil {
			return err
		}

		for _, platform := range platforms {
			name := fmt.Sprintf("%s-%s", binary, platform)
			err := generatePackage(name, templates.BinaryPackage, templates.BinaryPackageData{
				Name:     name,
				Binary:   binary,
				Platform: platform,
				Version:  version,
			})
			if err != nil {
				return err
			}
		}
	}

	return nil
}

func readVersion() (string, error) {
	contents, err := os.ReadFile(antoraConfigFile)
	if err != nil {
		return "", fmt.Errorf("failed to read Antora config file %q: %w", antoraConfigFile, err)
	}

	var config AntoraConfig
	err = yaml.Unmarshal(contents, &config)
	if err != nil {
		return "", fmt.Errorf("failed to parse Antora config file %q: %w", antoraConfigFile, err)
	}

	return config.Version + config.Prerelease, nil
}

func generatePackage(name string, templates *template.Template, data any) error {
	packageDir := filepath.Join(outDir, name)
	err := os.Mkdir(packageDir, dirPerm)
	if err != nil {
		return fmt.Errorf("failed to create package directory %q: %w", packageDir, err)
	}

	for _, template := range templates.Templates() {
		err := writeFile(packageDir, template, data)
		if err != nil {
			return err
		}
	}

	return nil
}

func writeFile(packageDir string, template *template.Template, data any) (err error) {
	path := filepath.Join(packageDir, template.Name())
	file, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("failed to create file %q: %w", path, err)
	}
	defer multierr.AppendInvoke(&err, multierr.Close(file))

	err = template.Execute(file, data)
	if err != nil {
		return fmt.Errorf("failed to generate file %q: %w", path, err)
	}

	return nil
}
