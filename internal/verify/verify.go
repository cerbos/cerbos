// Copyright 2021-2026 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package verify

import (
	"context"
	"fmt"
	"io/fs"
	"path/filepath"
	"runtime"
	"sort"
	"sync"

	enginev1 "github.com/cerbos/cerbos/api/genpb/cerbos/engine/v1"
	policyv1 "github.com/cerbos/cerbos/api/genpb/cerbos/policy/v1"
	"github.com/cerbos/cerbos/internal/evaluator"
	internaljsonschema "github.com/cerbos/cerbos/internal/jsonschema"
	"github.com/cerbos/cerbos/internal/util"
	"github.com/cerbos/cerbos/internal/validator"
)

const parallelismThreshold = 5

type Config struct {
	ExcludedResourcePolicyFQNs  map[string]struct{}
	ExcludedPrincipalPolicyFQNs map[string]struct{}
	IncludedTestNamesRegexp     string
	Trace                       bool
	SkipBatching                bool
	Workers                     uint
}

type SuiteResult struct {
	Suite *policyv1.TestResults_Suite
	Err   error
}

type Checker interface {
	Check(ctx context.Context, inputs []*enginev1.CheckInput, opts ...evaluator.CheckOpt) ([]*enginev1.CheckOutput, error)
}

func Verify(ctx context.Context, fsys fs.FS, eng Checker, conf Config) (*policyv1.TestResults, error) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	n, ch, err := VerifyStream(ctx, fsys, eng, conf)
	if err != nil {
		return nil, err
	}

	results := &policyv1.TestResults{
		Summary: &policyv1.TestResults_Summary{},
		Suites:  make([]*policyv1.TestResults_Suite, 0, n),
	}
	for sr := range ch {
		if sr.Err != nil {
			return nil, sr.Err
		}
		appendSuiteResult(results, sr.Suite)
	}

	sort.Slice(results.Suites, func(i, j int) bool {
		return results.Suites[i].File < results.Suites[j].File
	})
	return results, nil
}

// VerifyStream runs test suites and streams results as each suite completes.
// It returns the number of test suites, a channel of results, and any setup error.
// Callers may cancel the context to stop workers early and avoid unnecessary work.
func VerifyStream(ctx context.Context, fsys fs.FS, eng Checker, conf Config) (int, <-chan SuiteResult, error) {
	suiteDefs, fixtureDefs, err := discoverTestFiles(ctx, fsys)
	if err != nil {
		return 0, nil, err
	}

	testFilter, err := newTestFilter(&conf)
	if err != nil {
		return 0, nil, err
	}

	results := make(chan SuiteResult, len(suiteDefs))

	if len(suiteDefs) == 0 {
		close(results)
		return 0, results, nil
	}

	go func() {
		defer close(results)

		fixtures := newFixtureCache(fsys, fixtureDefs)

		workers := resolveWorkerCount(conf.Workers, len(suiteDefs))

		runSuite := func(file string) *policyv1.TestResults_Suite {
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
			fixture, err := fixtures.get(fixtureDir)
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

			return runTestSuite(ctx, eng, testFilter, file, suite, fixture, conf.Trace, conf.SkipBatching)
		}

		if workers == 1 {
			for _, file := range suiteDefs {
				suite := runSuite(file)
				select {
				case results <- SuiteResult{Suite: suite}:
				case <-ctx.Done():
					return
				}
			}
		} else {
			runConcurrent(ctx, suiteDefs, workers, runSuite, results)
		}
	}()

	return len(suiteDefs), results, nil
}

func discoverTestFiles(ctx context.Context, fsys fs.FS) (suiteDefs []string, fixtureDefs map[string]struct{}, err error) {
	fixtureDefs = make(map[string]struct{})

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

	return suiteDefs, fixtureDefs, err
}

type fixtureCache struct {
	fsys     fs.FS
	defs     map[string]struct{}
	fixtures map[string]*TestFixture
	mu       sync.Mutex
}

func newFixtureCache(fsys fs.FS, defs map[string]struct{}) *fixtureCache {
	return &fixtureCache{
		fsys:     fsys,
		defs:     defs,
		fixtures: make(map[string]*TestFixture, len(defs)),
	}
}

func (c *fixtureCache) get(path string) (*TestFixture, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if f, ok := c.fixtures[path]; ok {
		return f, nil
	}

	if _, exists := c.defs[path]; !exists {
		return nil, nil
	}

	f, err := LoadTestFixture(c.fsys, path, false)
	if err != nil {
		return nil, err
	}

	c.fixtures[path] = f
	return f, nil
}

func resolveWorkerCount(configured uint, numSuites int) int {
	if numSuites < parallelismThreshold {
		return 1
	}

	if configured == 1 {
		return 1
	}

	if configured == 0 {
		return runtime.NumCPU() + 4 //nolint:mnd
	}

	if int(configured) > numSuites {
		return numSuites
	}

	return int(configured)
}

func runConcurrent(ctx context.Context, suiteDefs []string, workers int, runSuite func(string) *policyv1.TestResults_Suite, results chan<- SuiteResult) {
	jobs := make(chan string, len(suiteDefs))
	var wg sync.WaitGroup

	for range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for file := range jobs {
				select {
				case <-ctx.Done():
					return
				default:
				}

				suite := runSuite(file)
				select {
				case results <- SuiteResult{Suite: suite}:
				case <-ctx.Done():
					return
				}
			}
		}()
	}

loop:
	for _, file := range suiteDefs {
		select {
		case jobs <- file:
		case <-ctx.Done():
			break loop
		}
	}
	close(jobs)

	wg.Wait()
}

func appendSuiteResult(results *policyv1.TestResults, suite *policyv1.TestResults_Suite) {
	results.Suites = append(results.Suites, suite)
	results.Summary.TestsCount += suite.Summary.TestsCount

	for _, tally := range suite.Summary.ResultCounts {
		incrementTally(results.Summary, tally.Result, tally.Count)
	}

	if suite.Summary.OverallResult > results.Summary.OverallResult {
		results.Summary.OverallResult = suite.Summary.OverallResult
	}
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
