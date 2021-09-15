// Copyright 2021 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package verify

import (
	"context"
	"fmt"
	effectv1 "github.com/cerbos/cerbos/api/genpb/cerbos/effect/v1"
	enginev1 "github.com/cerbos/cerbos/api/genpb/cerbos/engine/v1"
	policyv1 "github.com/cerbos/cerbos/api/genpb/cerbos/policy/v1"
	"github.com/cerbos/cerbos/internal/engine"
	"github.com/cerbos/cerbos/internal/util"
	"github.com/google/go-cmp/cmp"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
)

type Config struct {
	TestsDir string
	Run      string
}

type Result struct {
	Failed  bool          `json:"-"`
	Results []SuiteResult `json:"results"`
}

type SuiteResult struct {
	File    string       `json:"file"`
	Suite   string       `json:"suite"`
	Skipped bool         `json:"skipped,omitempty"`
	Tests   []TestResult `json:"tests"`
}

type TestResult struct {
	Name    string `json:"name"`
	Skipped bool   `json:"skipped,omitempty"`
	Failed  bool   `json:"failed,omitempty"`
	Error   string `json:"error,omitempty"`
}

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

	result := &Result{}
	err := fs.WalkDir(fsys, ".", func(path string, d fs.DirEntry, err error) error {
		if err := ctx.Err(); err != nil {
			return err
		}

		if err != nil {
			return err
		}

		if !d.IsDir() { // have own logic to process files
			return nil
		}

		if d.Name() == "testdata" {
			return fs.SkipDir
		}

		dirs, err := fs.ReadDir(fsys, path)
		if err != nil {
			return err
		}

		testFiles := make([]fs.DirEntry, 0)
		for _, d1 := range dirs {
			if d1.IsDir() {
				if d1.Name() == "testdata" {
					// load test fixture
				}
			} else if util.IsSupportedTestFile(d1.Name()) {
				testFiles = append(testFiles, d1)
			}
		}

		for _, d1 := range testFiles {
			ts := &policyv1.TestSuite{}
			path1 := filepath.Join(path, d1.Name())
			if err := util.LoadFromJSONOrYAML(fsys, path1, ts); err != nil {
				return err
			}

			suiteResult, failed := runTestSuite(ctx, eng, shouldRun, path1, ts)
			result.Results = append(result.Results, suiteResult)
			if failed {
				result.Failed = true
			}
		}

		return nil
	})

	return result, err
}

// EffectsMatch is a type created to make the diff output nicer.
type EffectsMatch map[string]effectv1.Effect

func runTestSuite(ctx context.Context, eng *engine.Engine, shouldRun func(string) bool, file string, ts *policyv1.TestSuite) (SuiteResult, bool) {
	failed := false

	sr := SuiteResult{File: file, Suite: ts.Name}
	if ts.Skip || !shouldRun(ts.Name) {
		sr.Skipped = true
		return sr, failed
	}

	for _, test := range ts.Tests {
		if err := ctx.Err(); err != nil {
			return sr, failed
		}

		testResult := TestResult{Name: test.Name}
		if test.Skip || !shouldRun(test.Name) {
			testResult.Skipped = true
			sr.Tests = append(sr.Tests, testResult)
			continue
		}

		actual, err := eng.Check(ctx, []*enginev1.CheckInput{test.Input})
		if err != nil {
			testResult.Failed = true
			testResult.Error = err.Error()
			failed = true
			sr.Tests = append(sr.Tests, testResult)
			continue
		}

		if len(actual) == 0 {
			testResult.Failed = true
			testResult.Error = "Empty response from server"
			failed = true
			sr.Tests = append(sr.Tests, testResult)
			continue
		}

		expectedResult := EffectsMatch(test.Expected)

		actualResult := make(EffectsMatch, len(actual[0].Actions))
		for key, actionEffect := range actual[0].Actions {
			actualResult[key] = actionEffect.Effect
		}

		if diff := cmp.Diff(expectedResult, actualResult); diff != "" {
			testResult.Failed = true
			testResult.Error = diff
			failed = true
		}

		sr.Tests = append(sr.Tests, testResult)
	}

	return sr, failed
}
