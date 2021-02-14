package pscript

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
)

type testCase struct {
	expr    string
	want    *Expr
	wantErr bool
}

func TestParse(t *testing.T) {
	fmt.Println(parser.String())

	doTestParse(t, "Comparison", genComparisonTestCases())
	//doTestParse(t, "Membership", genMembershipTestCases())
}

func doTestParse(t *testing.T, category string, testCases []testCase) {
	for i, tc := range testCases {
		tc := tc
		t.Run(fmt.Sprintf("%s_%02d", category, i), func(t *testing.T) {
			t.Logf("Parsing: %s", tc.expr)
			have, err := Parse(tc.expr)
			if tc.wantErr {
				require.Error(t, err)
				return
			}

			require.NoError(t, err)
			require.Equal(t, tc.want, have)
		})
	}
}

func genComparisonTestCases() []testCase {
	terms := map[string]Term{
		"$b.c.dee": Term{Reference: ptrS("$b.c.dee")},
		`"wibble"`: Term{Scalar: &Scalar{Str: ptrS("wibble")}},
		"23.2":     Term{Scalar: &Scalar{Number: ptrF(23.2)}},
		"25":       Term{Scalar: &Scalar{Number: ptrF(25)}},
		"true":     Term{Scalar: &Scalar{Bool: ptrB(true)}},
		"false":    Term{Scalar: &Scalar{Bool: ptrB(false)}},
	}

	var testCases []testCase

	for repr, t := range terms {
		for opStr, op := range operatorMap {
			testCases = append(testCases, testCase{
				expr: fmt.Sprintf("$a.b %s %s", opStr, repr),
				want: &Expr{
					Reference: "$a.b",
					Comparison: &Comparison{
						Op:      op,
						Operand: t,
					},
				},
			})
		}
	}

	return testCases
}

func genMembershipTestCases() []testCase {
	return []testCase{
		{
			expr: "$a.b IN $b.c.dee",
			want: &Expr{
				Reference:  "$a.b",
				Membership: &Membership{Reference: ptrS("$b.c.dee")},
			},
		},
		{
			expr: `$a.b IN { "wibble" , "wobble" , "fubble" }`,
			want: &Expr{
				Reference:  "$a.b",
				Membership: &Membership{Set: []*Scalar{{Str: ptrS("wibble")}, {Str: ptrS("wobble")}, {Str: ptrS("fubble")}}},
			},
		},
		{
			expr: `$a.b IN {1,2,3}`,
			want: &Expr{
				Reference:  "$a.b",
				Membership: &Membership{Set: []*Scalar{{Number: ptrF(1.0)}, {Number: ptrF(2.0)}, {Number: ptrF(3.0)}}},
			},
		},
	}
}

func ptrS(v string) *string {
	return &v
}

func ptrF(v float64) *float64 {
	return &v
}

func ptrB(v Bool) *Bool {
	return &v
}
