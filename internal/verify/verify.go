// Copyright 2021 Zenauth Ltd.
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
	Failed  bool   `json:"failed"`
	Error   string `json:"error,omitempty"`
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

		if d.Name() == TestDataDirectory {
			return fs.SkipDir
		}

		dirs, err := fs.ReadDir(fsys, path)
		if err != nil {
			return err
		}

		testFiles := make([]fs.DirEntry, 0)
		var testFixture *testFixture
		for _, d1 := range dirs {
			if d1.IsDir() {
				if d1.Name() == TestDataDirectory {
					testFixture, err = loadTestFixture(fsys, filepath.Join(path, d1.Name()))
					if err != nil {
						return err
					}
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

			suiteResult, failed := testFixture.runTestSuite(ctx, eng, shouldRun, path1, ts)
			result.Results = append(result.Results, suiteResult)
			if failed {
				result.Failed = true
			}
		}

		return nil
	})

	return result, err
}
