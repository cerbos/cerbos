package verify

import (
	"context"
	"fmt"
	"io/fs"
	"os"
	"regexp"

	"github.com/cerbos/cerbos/internal/engine"
	policyv1 "github.com/cerbos/cerbos/internal/genpb/policy/v1"
	sharedv1 "github.com/cerbos/cerbos/internal/genpb/shared/v1"
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
	Name     string `json:"name"`
	Skipped  bool   `json:"skipped,omitempty"`
	Failed   bool   `json:"failed,omitempty"`
	Expected string `json:"expected,omitempty"`
	Actual   string `json:"actual,omitempty"`
	Error    string `json:"error,omitempty"`
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

		if d.IsDir() {
			return nil
		}

		if !util.IsSupportedFileType(d.Name()) {
			return nil
		}

		ts := &policyv1.TestSuite{}
		if err := util.LoadFromJSONOrYAML(fsys, path, ts); err != nil {
			return err
		}

		suiteResult, failed := runTestSuite(ctx, eng, shouldRun, path, ts)
		result.Results = append(result.Results, suiteResult)
		if failed {
			result.Failed = true
		}

		return nil
	})

	return result, err
}

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

		expected := test.ExpectedEffect
		actual, err := eng.Check(ctx, test.Request)
		if err != nil {
			testResult.Failed = true
			testResult.Error = err.Error()
			failed = true
			continue
		}

		if actual != expected {
			testResult.Failed = true
			failed = true
		}

		testResult.Expected = sharedv1.Effect_name[int32(expected)]
		testResult.Actual = sharedv1.Effect_name[int32(actual)]

		sr.Tests = append(sr.Tests, testResult)
	}

	return sr, failed
}
