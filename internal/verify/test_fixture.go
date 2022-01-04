// Copyright 2021-2022 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package verify

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"path/filepath"

	"github.com/google/go-cmp/cmp"
	"google.golang.org/protobuf/proto"

	effectv1 "github.com/cerbos/cerbos/api/genpb/cerbos/effect/v1"
	enginev1 "github.com/cerbos/cerbos/api/genpb/cerbos/engine/v1"
	policyv1 "github.com/cerbos/cerbos/api/genpb/cerbos/policy/v1"
	"github.com/cerbos/cerbos/internal/engine"
	"github.com/cerbos/cerbos/internal/util"
)

type testFixture struct {
	principals map[string]*enginev1.Principal
	resources  map[string]*enginev1.Resource
	auxData    map[string]*enginev1.AuxData
}

const (
	principalsFileName = "principals"
	resourcesFileName  = "resources"
)

var auxDataFileNames = []string{"auxdata", "auxData", "aux_data"}

func loadTestFixture(fsys fs.FS, path string) (tf *testFixture, err error) {
	tf = new(testFixture)
	tf.principals, err = loadPrincipals(fsys, path)
	if err != nil {
		return nil, err
	}

	tf.resources, err = loadResources(fsys, path)
	if err != nil {
		return nil, err
	}

	tf.auxData, err = loadAuxData(fsys, path)
	if err != nil {
		return nil, err
	}

	return tf, nil
}

func loadResources(fsys fs.FS, path string) (map[string]*enginev1.Resource, error) {
	pb := &policyv1.TestFixture_Resources{}
	fp := filepath.Join(path, resourcesFileName)
	if err := loadFixtureElement(fsys, fp, pb); err != nil {
		if errors.Is(err, util.ErrNoMatchingFiles) {
			return nil, nil
		}
		return nil, err
	}

	return pb.Resources, nil
}

func loadPrincipals(fsys fs.FS, path string) (map[string]*enginev1.Principal, error) {
	pb := &policyv1.TestFixture_Principals{}
	fp := filepath.Join(path, principalsFileName)
	if err := loadFixtureElement(fsys, fp, pb); err != nil {
		if errors.Is(err, util.ErrNoMatchingFiles) {
			return nil, nil
		}
		return nil, err
	}

	return pb.Principals, nil
}

func loadAuxData(fsys fs.FS, path string) (map[string]*enginev1.AuxData, error) {
	pb := &policyv1.TestFixture_AuxData{}
	for _, fn := range auxDataFileNames {
		fp := filepath.Join(path, fn)
		if err := loadFixtureElement(fsys, fp, pb); err != nil {
			if errors.Is(err, util.ErrNoMatchingFiles) {
				continue
			}
			return nil, err
		}

		return pb.AuxData, nil
	}

	return nil, nil
}

func loadFixtureElement(fsys fs.FS, path string, pb proto.Message) error {
	file, err := util.OpenOneOfSupportedFiles(fsys, path)
	if err != nil || file == nil {
		return err
	}

	defer file.Close()
	return util.ReadJSONOrYAML(file, pb)
}

func (tf *testFixture) runTestSuite(ctx context.Context, eng *engine.Engine, shouldRun func(string) bool, file string, ts *policyv1.TestSuite) (SuiteResult, bool) {
	failed := false

	sr := SuiteResult{File: file, Suite: ts.Name}
	if ts.Skip {
		sr.Skipped = true
		return sr, failed
	}
	tests, err := tf.getTests(ts)
	if err != nil {
		failed = true
		sr.Tests = []TestResult{{
			Name:    TestName{TableTestName: "Failed to load the test suite"},
			Skipped: false,
			Failed:  true,
			Error:   err.Error(),
		}}
		return sr, failed
	}
	for _, test := range tests {
		if err := ctx.Err(); err != nil {
			return sr, failed
		}

		testResult := TestResult{Name: TestName{TableTestName: test.Name.TestTableName, PrincipalKey: test.Name.PrincipalKey}}
		if test.Skip || !shouldRun(fmt.Sprintf("%s/%s", ts.Name, test.Name.String())) {
			testResult.Skipped = true
			sr.Tests = append(sr.Tests, testResult)
			continue
		}

		traceBuf := new(bytes.Buffer)
		actual, err := eng.Check(ctx, []*enginev1.CheckInput{test.Input}, engine.WithWriterTraceSink(traceBuf))
		if err != nil {
			testResult.Failed = true
			testResult.Error = err.Error()
			testResult.EngineTrace = traceBuf.String()
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

		// EffectsMatch is a type created to make the diff output nicer.
		type EffectsMatch map[string]effectv1.Effect
		expectedResult := EffectsMatch(test.Expected)

		actualResult := make(EffectsMatch, len(actual[0].Actions))
		for key, actionEffect := range actual[0].Actions {
			actualResult[key] = actionEffect.Effect
		}

		if diff := cmp.Diff(expectedResult, actualResult); diff != "" {
			testResult.Failed = true
			testResult.Error = diff
			testResult.EngineTrace = traceBuf.String()
			failed = true
		}

		sr.Tests = append(sr.Tests, testResult)
	}

	return sr, failed
}

var (
	ErrAuxDataNotFound   = errors.New("auxData not found")
	ErrPrincipalNotFound = errors.New("principal not found")
	ErrResourceNotFound  = errors.New("resource not found")
)

func (tf *testFixture) lookupResource(k string) (*enginev1.Resource, bool) {
	if tf == nil {
		return nil, false
	}
	v, ok := tf.resources[k]
	return v, ok
}

func (tf *testFixture) lookupPrincipal(k string) (*enginev1.Principal, bool) {
	if tf == nil {
		return nil, false
	}
	v, ok := tf.principals[k]
	return v, ok
}

func (tf *testFixture) lookupAuxData(k string) (*enginev1.AuxData, bool) {
	if tf == nil {
		return nil, false
	}
	v, ok := tf.auxData[k]
	return v, ok
}

func (tf *testFixture) getTests(ts *policyv1.TestSuite) (tests []*policyv1.Test, err error) {
	for _, table := range ts.Tests {
		for _, expected := range table.Expected {
			principal, ok := ts.Principals[expected.Principal]
			if !ok {
				principal, ok = tf.lookupPrincipal(expected.Principal)
				if !ok {
					return nil, fmt.Errorf("%w:%q", ErrPrincipalNotFound, expected.Principal)
				}
			}

			resource, ok := ts.Resources[table.Input.Resource]
			if !ok {
				resource, ok = tf.lookupResource(table.Input.Resource)
				if !ok {
					return nil, fmt.Errorf("%w:%q", ErrResourceNotFound, table.Input.Resource)
				}
			}

			var auxData *enginev1.AuxData
			if adKey := table.Input.AuxData; adKey != "" {
				auxData, ok = ts.AuxData[adKey]
				if !ok {
					auxData, ok = tf.lookupAuxData(adKey)
					if !ok {
						return nil, fmt.Errorf("%w:%q", ErrAuxDataNotFound, adKey)
					}
				}
			}

			test := &policyv1.Test{
				Name:        &policyv1.Test_TestName{TestTableName: table.Name, PrincipalKey: expected.Principal},
				Description: table.Description,
				Skip:        table.Skip,
				SkipReason:  table.SkipReason,
				Input: &enginev1.CheckInput{
					RequestId: table.Input.RequestId,
					Resource:  resource,
					Principal: principal,
					AuxData:   auxData,
					Actions:   table.Input.Actions,
				},
				Expected: expected.Actions,
			}
			tests = append(tests, test)
		}
	}

	return tests, nil
}
