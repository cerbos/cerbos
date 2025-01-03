// Copyright 2021-2025 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sort"

	"github.com/alecthomas/kong"
	"github.com/gobwas/glob"
	"golang.org/x/tools/go/packages"
	"gopkg.in/yaml.v3"
)

type splitCmd struct {
	IgnoreFile string `type:"existingfile" optional:""`
	Kind       string
	Index      int
	Total      int
}

func (cmd *splitCmd) Run(k *kong.Kong) error {
	times, err := readTestTimes()
	if err != nil {
		return err
	}

	packages, err := listPackages(cmd.IgnoreFile)
	if err != nil {
		return err
	}

	buckets := make(testBuckets, cmd.Total)

	for _, time := range times[cmd.Kind] {
		if _, ok := packages[time.Package]; ok {
			buckets.LeastFull().Add(time)
			delete(packages, time.Package)
		}
	}

	for _, pkg := range packages.Packages() {
		buckets.LeastFull().Add(testTime{Package: pkg, Time: newPackageTime})
	}

	fmt.Fprintf(k.Stderr, "%s test split %d/%d (expected time %.1fs)\n\n", cmd.Kind, cmd.Index+1, cmd.Total, buckets[cmd.Index].TotalTime)

	for _, pkg := range buckets[cmd.Index].Packages {
		fmt.Fprintln(k.Stderr, pkg)
		fmt.Fprintln(k.Stdout, pkg)
	}

	fmt.Fprintln(k.Stderr)

	return nil
}

func readTestTimes() (testTimesByKind, error) {
	data, err := os.ReadFile(testTimesPath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return testTimesByKind{}, nil
		}
		return nil, fmt.Errorf("failed to read test times: %w", err)
	}

	var result testTimesByKind
	err = json.Unmarshal(data, &result)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal test times: %w", err)
	}

	return result, nil
}

type packageSet map[string]struct{}

func (pkgs packageSet) Packages() []string {
	result := make([]string, 0, len(pkgs))

	for pkg := range pkgs {
		result = append(result, pkg)
	}

	sort.Strings(result)

	return result
}

func listPackages(ignoreFile string) (packageSet, error) {
	var ignoredPkgs globList
	if ignoreFile != "" {
		ignore, err := loadIgnoreList(ignoreFile)
		if err != nil {
			return nil, fmt.Errorf("failed to load ignore list from %q: %w", ignoreFile, err)
		}
		ignoredPkgs = ignore
	}

	packages, err := packages.Load(&packages.Config{Mode: packages.NeedName}, "./...")
	if err != nil {
		return nil, fmt.Errorf("failed to list Go packages: %w", err)
	}

	result := make(packageSet, len(packages))

	for _, pkg := range packages {
		if !ignoredPkgs.Matches(pkg.PkgPath) {
			result[pkg.PkgPath] = struct{}{}
		}
	}

	return result, nil
}

type globList []glob.Glob

func (gl globList) Matches(value string) bool {
	for _, g := range gl {
		if g.Match(value) {
			return true
		}
	}

	return false
}

func loadIgnoreList(ignoreFile string) (globList, error) {
	listBytes, err := os.ReadFile(ignoreFile)
	if err != nil {
		return nil, fmt.Errorf("failed to read %q: %w", ignoreFile, err)
	}

	var ignoreList struct {
		Ignore []string `yaml:"ignore"`
	}
	if err := yaml.Unmarshal(listBytes, &ignoreList); err != nil {
		return nil, fmt.Errorf("failed to unmarshal YAML: %w", err)
	}

	ignoreGlobs := make(globList, len(ignoreList.Ignore))
	for i, gp := range ignoreList.Ignore {
		g, err := glob.Compile(gp)
		if err != nil {
			return nil, fmt.Errorf("failed to compile glob pattern %q: %w", gp, err)
		}

		ignoreGlobs[i] = g
	}

	return ignoreGlobs, nil
}
