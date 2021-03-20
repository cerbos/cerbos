package compile_test

import (
	"errors"
	"fmt"
	"math/rand"
	"testing"
	"time"
	"unsafe"

	"github.com/ghodss/yaml"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/encoding/protojson"

	"github.com/charithe/menshen/pkg/compile"
	policyv1 "github.com/charithe/menshen/pkg/generated/policy/v1"
	sharedv1 "github.com/charithe/menshen/pkg/generated/shared/v1"
	testv1 "github.com/charithe/menshen/pkg/generated/test/v1"
	"github.com/charithe/menshen/pkg/namer"
	"github.com/charithe/menshen/pkg/test"
)

const letterBytes = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
const (
	letterIdxBits = 6                    // 6 bits to represent a letter index
	letterIdxMask = 1<<letterIdxBits - 1 // All 1-bits, as many as letterIdxBits
	letterIdxMax  = 63 / letterIdxBits   // # of letter indices fitting in 63 bits
)

var src = rand.NewSource(time.Now().UnixNano())

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

func BenchmarkCompile(b *testing.B) {
	cases := make([]*compile.Unit, b.N)
	for i := 0; i < b.N; i++ {
		cases[i] = mkUnit()
	}

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		c := cases[i]
		compileChan := make(chan *compile.Unit, 1)
		compileChan <- c
		close(compileChan)

		compiler, err := compile.Compile(compileChan)
		if err != nil {
			b.Errorf("ERROR compile error: %v", err)
		}

		if eval := compiler.GetEvaluator(c.ModID); eval == nil {
			b.Errorf("ERROR: Evaluator is nil")
		}
	}
}

func mkUnit() *compile.Unit {
	numDerivedRolesFiles := 10
	numDerivedRolesPerFile := 10

	x := rand.Intn(100000) //nolint:gosec
	resource := fmt.Sprintf("resource_%d", x)
	rpName := fmt.Sprintf("%s_default", resource)

	pc := &compile.Unit{
		Definitions: make(map[string]*policyv1.Policy),
		ModToFile:   make(map[namer.ModuleID]string),
	}

	rp := test.NewResourcePolicyBuilder(resource, "default")
	for i := 0; i < numDerivedRolesFiles; i++ {
		drName := fmt.Sprintf("derived_%02d", i)
		rr := test.NewResourceRule(fmt.Sprintf("action_%d", i)).WithEffect(sharedv1.Effect_EFFECT_ALLOW).WithMatchExpr(mkMatchExpr(3)...)

		dr := test.NewDerivedRolesBuilder(drName)
		for j := 0; j < numDerivedRolesPerFile; j++ {
			name := mkRandomStr(8)
			dr = dr.AddRoleWithMatch(name, mkRandomRoleNames(5), mkMatchExpr(5)...)
			rr = rr.WithDerivedRoles(name)
		}

		drPol := dr.Build()
		pc.Definitions[drName] = drPol
		pc.ModToFile[namer.GenModuleID(drPol)] = drName
		rp = rp.WithDerivedRolesImports(drName).WithRules(rr.Build())
	}

	rpPol := rp.Build()
	pc.Definitions[rpName] = rpPol
	pc.ModToFile[namer.GenModuleID(rpPol)] = rpName
	pc.ModID = namer.GenModuleID(rpPol)

	return pc
}

func mkMatchExpr(n int) []string {
	exprs := make([]string, n)
	for i := 0; i < n; i++ {
		exprs[i] = fmt.Sprintf("request.principal.attr.attr_%d == request.resource.attr.attr_%d", i, i)
	}

	return exprs
}

func mkRandomRoleNames(n int) []string {
	roles := make([]string, n)
	for i := 0; i < n; i++ {
		roles[i] = mkRandomStr(5)
	}

	return roles
}

// StackOverflow: purveyors of impostor syndrome
// https://stackoverflow.com/a/31832326/7364928
func mkRandomStr(n int) string {
	b := make([]byte, n)
	// A src.Int63() generates 63 random bits, enough for letterIdxMax characters!
	for i, cache, remain := n-1, src.Int63(), letterIdxMax; i >= 0; {
		if remain == 0 {
			cache, remain = src.Int63(), letterIdxMax
		}
		if idx := int(cache & letterIdxMask); idx < len(letterBytes) {
			b[i] = letterBytes[idx]
			i--
		}
		cache >>= letterIdxBits
		remain--
	}

	return *(*string)(unsafe.Pointer(&b))
}
