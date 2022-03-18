// Copyright 2021-2022 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package verify

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"

	policyv1 "github.com/cerbos/cerbos/api/genpb/cerbos/policy/v1"
	"github.com/cerbos/cerbos/internal/engine"
	"github.com/cerbos/cerbos/internal/util"
)

type Config struct {
	TestsDir string
	Run      string
	Trace    bool
}

var ErrTestFixtureNotFound = errors.New("test fixture not found")

// Verify runs the test suites from the provided directory.
func Verify(ctx context.Context, eng *engine.Engine, conf Config) (*policyv1.TestResults, error) {
	fsys := os.DirFS(conf.TestsDir)
	return doVerify(ctx, fsys, eng, conf)
}

func doVerify(ctx context.Context, fsys fs.FS, eng *engine.Engine, conf Config) (*policyv1.TestResults, error) {
	var shouldRun func(string) bool

	if conf.Run == "" {
		shouldRun = func(_ string) bool { return true }
	} else {
		runRegex, err := regexp.Compile(conf.Run)
		if err != nil {
			return nil, fmt.Errorf("invalid run specification: %w", err)
		}

		shouldRun = func(name string) bool { return runRegex.MatchString(name) }
	}

	var suiteDefs []string
	fixtureDefs := make(map[string]struct{})

	err := fs.WalkDir(fsys, ".", func(path string, d fs.DirEntry, err error) error {
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

	fixtures := make(map[string]*testFixture, len(fixtureDefs))

	getFixture := func(path string) (*testFixture, error) {
		f, ok := fixtures[path]
		if ok {
			return f, nil
		}

		if _, exists := fixtureDefs[path]; exists {
			f, err := loadTestFixture(fsys, path)
			if err != nil {
				return nil, err
			}

			fixtures[path] = f
			return f, nil
		}

		return nil, nil
	}

	runTestSuite := func(file string) *policyv1.TestResults_Suite {
		suite := &policyv1.TestSuite{}
		err := util.LoadFromJSONOrYAML(fsys, file, suite)
		if err == nil {
			err = suite.Validate()
		}
		if err != nil {
			return &policyv1.TestResults_Suite{
				File:   file,
				Name:   "Unknown",
				Result: policyv1.TestResults_RESULT_ERRORED,
				Error:  fmt.Sprintf("failed to load test suite: %v", err),
			}
		}

		fixtureDir := filepath.Join(filepath.Dir(file), util.TestDataDirectory)
		fixture, err := getFixture(fixtureDir)
		if err != nil {
			return &policyv1.TestResults_Suite{
				File:   file,
				Name:   suite.Name,
				Result: policyv1.TestResults_RESULT_ERRORED,
				Error:  fmt.Sprintf("failed to load test fixtures from %s: %v", fixtureDir, err),
			}
		}

		return fixture.runTestSuite(ctx, eng, shouldRun, file, suite, conf.Trace)
	}

	results := &policyv1.TestResults{}

	for _, sd := range suiteDefs {
		suiteResult := runTestSuite(sd)
		results.Suites = append(results.Suites, suiteResult)
		if suiteResult.Result > results.Result {
			results.Result = suiteResult.Result
		}
	}

	return results, err
}
