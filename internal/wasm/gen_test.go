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

//go:embed templates/*.rs.tmpl
var templatesFS embed.FS

/*
 */

func TestClasses(t *testing.T) {
	is := require.New(t)
	tmpl, err := template.ParseFS(templatesFS, "templates/*.rs.tmpl")

	is.NoError(err)
	is.NotNil(tmpl)
	s, err := jsonschema.Compile(path.Join("testdata", "leave_request.json"))
	is.NoError(err)
	props, err := convert(s)
	is.NoError(err)
	tmpl.ExecuteTemplate(os.Stdout, "request", props)
}
