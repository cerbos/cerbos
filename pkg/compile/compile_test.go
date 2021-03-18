package compile_test

import (
	"errors"
	"testing"

	"github.com/ghodss/yaml"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/encoding/protojson"

	"github.com/charithe/menshen/pkg/compile"
	testv1 "github.com/charithe/menshen/pkg/generated/test/v1"
	"github.com/charithe/menshen/pkg/namer"
	"github.com/charithe/menshen/pkg/test"
)

func TestCompile(t *testing.T) {
	testCases := test.LoadTestCases(t, "compile")

	for _, tcase := range testCases {
		tcase := tcase
		t.Run(tcase.Name, func(t *testing.T) {
			tc := readTestCase(t, tcase.Input)

			inputChan := mkInputChan(t, tc)

			haveRes, haveErr := compile.Compile(inputChan)
			if len(tc.WantErrors) > 0 {
				errList := new(compile.ErrorList)
				require.True(t, errors.As(haveErr, errList))

				require.Len(t, *errList, len(tc.WantErrors))
				for _, err := range *errList {
					require.Contains(t, tc.WantErrors, err.Error())
				}

				return
			}

			require.NotNil(t, haveRes)
		})
	}
}

func readTestCase(t *testing.T, data []byte) *testv1.CompileTestCase {
	t.Helper()

	jsonBytes, err := yaml.YAMLToJSON(data)
	require.NoError(t, err)

	tc := &testv1.CompileTestCase{}
	require.NoError(t, protojson.Unmarshal(jsonBytes, tc))

	return tc
}

func mkInputChan(t *testing.T, tc *testv1.CompileTestCase) chan *compile.Unit {
	t.Helper()

	p := &compile.Unit{
		Definitions: tc.InputDefs,
		ModToFile:   make(map[namer.ModuleID]string, len(tc.InputDefs)),
	}

	for fileName, pol := range tc.InputDefs {
		modID := namer.GenModuleID(pol)
		p.ModToFile[modID] = fileName

		if fileName == tc.MainDef {
			p.ModID = modID
		}
	}

	inputChan := make(chan *compile.Unit, 1)
	inputChan <- p
	close(inputChan)

	return inputChan
}
