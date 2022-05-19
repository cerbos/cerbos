package wasm

import (
	"testing"
	"embed"
	"text/template"
	"github.com/stretchr/testify/require"
	"os"
	"github.com/santhosh-tekuri/jsonschema/v5"
	"path"
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
	tmpl.ExecuteTemplate(os.Stdout, "lib", props)
}

type Policy struct {
	Rules []Rule
}

type Rule struct {
	Roles   []string
	Actions []string
}

func TestCheck(t *testing.T) {
	is := require.New(t)
	tmpl, err := template.ParseFS(templatesFS, "templates/*.tmpl")

	is.NoError(err)
	is.NotNil(tmpl)

	policy := Policy{
		Rules: []Rule{{
			Roles:   []string{"admin", "manager"},
			Actions: []string{"read", "update"},
		}},
	}
	tmpl.ExecuteTemplate(os.Stdout, "check", policy)
}
