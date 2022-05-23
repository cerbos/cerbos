package wasm

import (
	"testing"
	"embed"
	"text/template"
	"github.com/stretchr/testify/require"
	"os"
	"github.com/santhosh-tekuri/jsonschema/v5"
	"path"
	runtimev1 "github.com/cerbos/cerbos/api/genpb/cerbos/runtime/v1"
	policyv1 "github.com/cerbos/cerbos/api/genpb/cerbos/policy/v1"
	"google.golang.org/protobuf/encoding/protojson"
	"github.com/cerbos/cerbos/internal/compile"
)

//go:embed templates/*.tmpl
var templatesFS embed.FS

func TestClasses(t *testing.T) {
	is := require.New(t)
	tmpl, err := template.ParseFS(templatesFS, "templates/*.tmpl")

	is.NoError(err)
	is.NotNil(tmpl)
	s, err := jsonschema.Compile(path.Join("testdata", "leave_request.json"))
	is.NoError(err)
	props, err := ConvertSchema(s)
	is.NoError(err)
	err = tmpl.ExecuteTemplate(os.Stdout, "request", struct {
		Resource  []*Field
		Principal []*Field
	}{props, nil})
	is.NoError(err)
}

func TestCheck(t *testing.T) {
	is := require.New(t)
	tmpl, err := template.ParseFS(templatesFS, "templates/*.tmpl")

	is.NoError(err)
	is.NotNil(tmpl)

	policy := Policy{
		Rules: []*Rule{{
			Roles:     []string{"admin", "manager"},
			Actions:   []string{"read", "update"},
			Effect:    "EFFECT_ALLOW",
			Condition: getCondition(t),
		}},
	}
	err = tmpl.ExecuteTemplate(os.Stdout, "check", policy)
	is.NoError(err)
}

func getCondition(t *testing.T) *runtimev1.Condition {
	t.Helper()

	buf := []byte(`{ "match": { "expr": "request.resource.attr.geography == \"UK\"" } }`)
	c := new(policyv1.Condition)
	err := protojson.Unmarshal(buf, c)
	require.NoError(t, err)

	cond, err := compile.Condition(c)
	require.NoError(t, err)
	require.NotNil(t, cond)

	return cond
}
