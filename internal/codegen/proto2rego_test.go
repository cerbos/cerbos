// Copyright 2021 Zenauth Ltd.

package codegen_test

import (
	"bytes"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/open-policy-agent/opa/ast"
	"github.com/open-policy-agent/opa/format"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/structpb"

	"github.com/cerbos/cerbos/internal/codegen"
	enginev1 "github.com/cerbos/cerbos/internal/genpb/engine/v1"
)

var dummy ast.Value

func TestMarshalProtoToRego(t *testing.T) {
	testCases := []struct {
		name    string
		input   func(testing.TB) proto.Message
		wantErr bool
	}{
		{
			name:  "nil value",
			input: func(testing.TB) proto.Message { return nil },
		},
		{
			name:  "A bit of everything",
			input: mkProto,
		},
	}

	for _, tc := range testCases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			input := tc.input(t)

			have, err := codegen.MarshalProtoToRego(input)
			if tc.wantErr {
				require.Error(t, err)
				return
			}

			require.NoError(t, err)

			want := toValue(t, input)

			if want.Compare(have) != 0 {
				wantF := format.MustAst(want)
				haveF := format.MustAst(have)
				t.Errorf("%s", cmp.Diff(wantF, haveF))
			}
		})
	}
}

func BenchmarkMarshalProtoToRego(b *testing.B) {
	b.ReportAllocs()

	msg := mkProto(b)

	b.Run("via_json", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			dummy = toValue(b, msg)
		}
	})

	b.Run("direct", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			v, err := codegen.MarshalProtoToRego(msg)
			require.NoError(b, err)

			dummy = v
		}
	})
}

func toValue(tb testing.TB, msg proto.Message) ast.Value {
	tb.Helper()

	jsonBytes, err := protojson.Marshal(msg)
	require.NoError(tb, err, "Failed to marshal JSON")

	value, err := ast.ValueFromReader(bytes.NewReader(jsonBytes))
	require.NoError(tb, err, "Failed to convert to value")

	return value
}

func mkProto(tb testing.TB) proto.Message {
	tb.Helper()

	m := make(map[string]*structpb.Value)
	var err error

	m["nilVal"] = structpb.NewNullValue()
	m["boolVal"] = structpb.NewBoolValue(true)
	m["intVal"] = structpb.NewNumberValue(float64(123))
	m["floatVal"] = structpb.NewNumberValue(12.34)
	m["stringVal"] = structpb.NewStringValue("test")

	m["byteVal"], err = structpb.NewValue([]byte("test"))
	require.NoError(tb, err)

	m["listVal"], err = structpb.NewValue([]interface{}{"a", "b", "c"})
	require.NoError(tb, err)

	m["mapVal"], err = structpb.NewValue(map[string]interface{}{"x": 12, "y": []interface{}{1, 2, 3}})
	require.NoError(tb, err)

	return &enginev1.CheckInput{
		RequestId: "test",
		Actions:   []string{"view:public"},
		Resource: &enginev1.Resource{
			Kind:          "leave_request",
			PolicyVersion: "20210210",
			Id:            "XX125",
			Attr:          m,
		},
		Principal: &enginev1.Principal{
			Id:            "john",
			PolicyVersion: "20210210",
			Roles:         []string{"employee"},
			Attr:          m,
		},
	}
}
