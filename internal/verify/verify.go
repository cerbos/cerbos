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
}

type Result struct {
	Results []SuiteResult `json:"results"`
	Failed  bool          `json:"-"`
}

type SuiteResult struct {
	File    string       `json:"file"`
	Suite   string       `json:"suite"`
	Tests   []TestResult `json:"tests"`
	Skipped bool         `json:"skipped,omitempty"`
	Failed  bool         `json:"failed,omitempty"`
}

type TestName struct {
	TableTestName string `json:"name"`
	PrincipalKey  string `json:"principal"`
	ResourceKey   string `json:"resource"`
}

func (r TestName) String() string {
	return fmt.Sprintf("'%s' for resource '%s' by principal '%s'", r.TableTestName, r.ResourceKey, r.PrincipalKey)
}

type TestResult struct {
	Error       string   `json:"error,omitempty"`
	EngineTrace string   `json:"engineTrace,omitempty"`
	Name        TestName `json:"case"`
	Skipped     bool     `json:"skipped,omitempty"`
	Failed      bool     `json:"failed"`
}

var ErrTestFixtureNotFound = errors.New("test fixture not found")

// Verify runs the test suites from the provided directory.
func Verify(ctx context.Context, eng *engine.Engine, conf Config) (*Result, error) {
	fsys := os.DirFS(conf.TestsDir)
	return doVerify(ctx, fsys, eng, conf)
}

func doVerify(ctx context.Context, fsys fs.FS, eng *engine.Engine, conf Config) (*Result, error) {
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

	result := &Result{}

	for _, sd := range suiteDefs {
		suite := &policyv1.TestSuite{}
		err := util.LoadFromJSONOrYAML(fsys, sd, suite)
		if err == nil {
			err = suite.Validate()
		}
		if err != nil {
			result.Results = append(result.Results, SuiteResult{
				File:    sd,
				Suite:   fmt.Sprintf("UNKNOWN: failed to load test suite: %v", err),
				Skipped: false,
				Failed:  true,
			})
			result.Failed = true
			continue
		}

		fixtureDir := filepath.Join(filepath.Dir(sd), util.TestDataDirectory)
		fixture, err := getFixture(fixtureDir)
		if err != nil {
			result.Results = append(result.Results, SuiteResult{
				File:   sd,
				Suite:  suite.Name,
				Failed: true,
				Tests: []TestResult{
					{
						Name:   TestName{TableTestName: "*", PrincipalKey: "*", ResourceKey: "*"},
						Failed: true,
						Error:  fmt.Sprintf("failed to load test fixtures from %s: %v", fixtureDir, err),
					},
				},
			})
			result.Failed = true
			continue
		}

		suiteResult, failed := fixture.runTestSuite(ctx, eng, shouldRun, sd, suite)
		result.Results = append(result.Results, suiteResult)
		if failed {
			result.Failed = true
		}
	}

	return result, err
}
