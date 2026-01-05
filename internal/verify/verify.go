// Copyright 2021-2026 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package verify

import (
	"context"
	"fmt"
	"io/fs"
	"path/filepath"
	"sort"

	enginev1 "github.com/cerbos/cerbos/api/genpb/cerbos/engine/v1"
	policyv1 "github.com/cerbos/cerbos/api/genpb/cerbos/policy/v1"
	"github.com/cerbos/cerbos/internal/evaluator"
	internaljsonschema "github.com/cerbos/cerbos/internal/jsonschema"
	"github.com/cerbos/cerbos/internal/util"
	"github.com/cerbos/cerbos/internal/validator"
)

type Config struct {
	ExcludedResourcePolicyFQNs  map[string]struct{}
	ExcludedPrincipalPolicyFQNs map[string]struct{}
	IncludedTestNamesRegexp     string
	Trace                       bool
}

type Checker interface {
	Check(ctx context.Context, inputs []*enginev1.CheckInput, opts ...evaluator.CheckOpt) ([]*enginev1.CheckOutput, error)
}

// Verify runs the test suites from the provided directory.
func Verify(ctx context.Context, fsys fs.FS, eng Checker, conf Config) (*policyv1.TestResults, error) {
	testFilter, err := newTestFilter(&conf)
	if err != nil {
		return nil, err
	}
	var suiteDefs []string
	fixtureDefs := make(map[string]struct{})

	err = fs.WalkDir(fsys, ".", func(path string, d fs.DirEntry, err error) error {
		if err := ctx.Err(); err != nil {
			return err
		}

		if err != nil {
			return err
		}

		if d.IsDir() {
			if d.Name() == util.TestDataDirectory {
				fixtureDefs[path] = struct{}{}
				return fs.SkipDir
			}

			return nil
		}

		if util.IsSupportedTestFile(path) {
			suiteDefs = append(suiteDefs, path)
		}

		return nil
	})
	if err != nil {
		return nil, err
	}

	fixtures := make(map[string]*TestFixture, len(fixtureDefs))

	getFixture := func(path string) (*TestFixture, error) {
		f, ok := fixtures[path]
		if ok {
			return f, nil
		}

		if _, exists := fixtureDefs[path]; exists {
			f, err := LoadTestFixture(fsys, path, false)
			if err != nil {
				return nil, err
			}

			fixtures[path] = f
			return f, nil
		}

		return nil, nil
	}

	runTestSuite := func(file string) *policyv1.TestResults_Suite {
		if err := internaljsonschema.ValidateTest(fsys, file); err != nil {
			return &policyv1.TestResults_Suite{
				File: file,
				Name: "Unknown",
				Summary: &policyv1.TestResults_Summary{
					OverallResult: policyv1.TestResults_RESULT_ERRORED,
				},
				Error: err.Error(),
			}
		}

		suite := &policyv1.TestSuite{}
		err := util.LoadFromJSONOrYAML(fsys, file, suite)
		if err == nil {
			err = validator.Validate(suite)
		}
		if err != nil {
			return &policyv1.TestResults_Suite{
				File: file,
				Name: "Unknown",
				Summary: &policyv1.TestResults_Summary{
					OverallResult: policyv1.TestResults_RESULT_ERRORED,
				},
				Error: fmt.Sprintf("failed to load test suite: %v", err),
			}
		}

		fixtureDir := filepath.Join(filepath.Dir(file), util.TestDataDirectory)
		fixture, err := getFixture(fixtureDir)
		if err != nil {
			return &policyv1.TestResults_Suite{
				File:        file,
				Name:        suite.Name,
				Description: suite.Description,
				Summary: &policyv1.TestResults_Summary{
					OverallResult: policyv1.TestResults_RESULT_ERRORED,
				},
				Error: fmt.Sprintf("failed to load test fixtures from %s: %v", fixtureDir, err),
			}
		}

		return runTestSuite(ctx, eng, testFilter, file, suite, fixture, conf.Trace)
	}

	results := &policyv1.TestResults{
		Summary: &policyv1.TestResults_Summary{},
	}

	for _, sd := range suiteDefs {
		suiteResult := runTestSuite(sd)

		results.Suites = append(results.Suites, suiteResult)

		results.Summary.TestsCount += suiteResult.Summary.TestsCount

		for _, tally := range suiteResult.Summary.ResultCounts {
			incrementTally(results.Summary, tally.Result, tally.Count)
		}

		if suiteResult.Summary.OverallResult > results.Summary.OverallResult {
			results.Summary.OverallResult = suiteResult.Summary.OverallResult
		}
	}

	return results, err
}

func incrementTally(summary *policyv1.TestResults_Summary, result policyv1.TestResults_Result, delta uint32) {
	addTally(summary, result).Count += delta
}

func addTally(summary *policyv1.TestResults_Summary, result policyv1.TestResults_Result) *policyv1.TestResults_Tally {
	for _, tally := range summary.ResultCounts {
		if tally.Result == result {
			return tally
		}
	}

	tally := &policyv1.TestResults_Tally{Result: result}

	summary.ResultCounts = append(summary.ResultCounts, tally)
	sort.Slice(summary.ResultCounts, func(i, j int) bool {
		return summary.ResultCounts[i].Result < summary.ResultCounts[j].Result
	})

	return tally
}
