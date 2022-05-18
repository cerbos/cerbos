package wasm

import (
	"testing"
	"embed"
	"text/template"
	"github.com/stretchr/testify/require"
	"os"
)

//go:embed templates/*.rs.tmpl
var templatesFS embed.FS

/*
 */

type Property struct {
	Type     string
	Name     string
	Required bool
}

func TestClasses(t *testing.T) {
	is := require.New(t)
	tmpl, err := template.ParseFS(templatesFS, "templates/*.rs.tmpl")

	is.NoError(err)
	is.NotNil(tmpl)
	props := []Property{
		{"vec", "amount", true},
		{"string", "department", true},
		{"string", "team", false},
	}
	tmpl.ExecuteTemplate(os.Stdout, "request", props)
}
