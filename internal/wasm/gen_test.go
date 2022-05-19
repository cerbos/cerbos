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
	props, err := convert(s)
	is.NoError(err)
	err = tmpl.ExecuteTemplate(os.Stdout, "lib", props)
	is.NoError(err)
}

func TestCheck(t *testing.T) {
	is := require.New(t)
	tmpl, err := template.ParseFS(templatesFS, "templates/*.tmpl")

	is.NoError(err)
	is.NotNil(tmpl)

	policy := Policy{
		Rules: []Rule{{
			Roles:     []string{"admin", "manager"},
			Actions:   []string{"read", "update"},
			Effect:    "EFFECT_ALLOW",
			Condition: &runtimev1.Condition{},
		}},
	}
	err = tmpl.ExecuteTemplate(os.Stdout, "check", policy)
	is.NoError(err)
}
