package wasm

import (
	"github.com/cerbos/cerbos/internal/schema"
	"github.com/cerbos/cerbos/internal/compile"
	"github.com/stretchr/testify/require"
	"path/filepath"
	"github.com/cerbos/cerbos/internal/storage/disk"
	"testing"
	"runtime"
	"context"
	"github.com/cerbos/cerbos/internal/namer"
	"os"
	"github.com/santhosh-tekuri/jsonschema/v5"
	"io"
	"text/template"
	"strings"
	"net/url"
)

func pathToDir(tb testing.TB, dir string) string {
	tb.Helper()

	_, currFile, _, ok := runtime.Caller(0)
	if !ok {
		tb.Error("Failed to detect testdata directory")
		return ""
	}

	return filepath.Join(filepath.Dir(currFile), "testdata", dir)
}

func mkCompiler(t *testing.T) (*compile.Manager, *jsonschema.Compiler) {
	t.Helper()

	dir := pathToDir(t, "store")

	ctx, cancelFunc := context.WithCancel(context.Background())
	t.Cleanup(cancelFunc)

	store, err := disk.NewStore(ctx, &disk.Conf{Directory: dir})
	require.NoError(t, err)

	schemaConf := schema.NewConf(schema.EnforcementReject)
	schemaMgr := schema.NewFromConf(ctx, store, schemaConf)

	compiler := jsonschema.NewCompiler()
	compiler.AssertFormat = true
	compiler.AssertContent = true
	compiler.LoadURL = func(path string) (io.ReadCloser, error) {
		u, err := url.Parse(path)
		if err != nil {
			return nil, err
		}
		p := strings.TrimPrefix(u.Path, "/")
		return store.LoadSchema(ctx, p)
	}

	return compile.NewManagerFromDefaultConf(ctx, store, schemaMgr), compiler
}

func TestNewCompiler(t *testing.T) {
	is := require.New(t)

	compiler, _ := mkCompiler(t)
	is.NotNil(compiler)
}

func TestGenPolicy(t *testing.T) {
	tmpl, err := template.ParseFS(templatesFS, "templates/*.tmpl")

	resource, policyVer, scope := "leave_request", "staging", ""
	resourceModID := namer.ResourcePolicyModuleID(resource, policyVer, scope)
	mngr, compiler := mkCompiler(t)
	ctx := context.Background()
	rps, err := mngr.Get(ctx, resourceModID)
	is := require.New(t)
	is.NoError(err)
	is.NotNil(rps)
	rp := rps.GetResourcePolicy()
	is.NotNil(rp)

	s, err := compiler.Compile(rp.Schemas.ResourceSchema.Ref)
	is.NoError(err)

	r, err := convert(s)
	is.NoError(err)

	s, err = compiler.Compile(rp.Schemas.PrincipalSchema.Ref)
	is.NoError(err)
	p, err := convert(s)
	is.NoError(err)

	rules, err := convertPolicy(rp)
	is.NoError(err)

	policy := Policy{
		Rules: rules,
		Schema: &Schema{
			Principal: p,
			Resource:  r,
		},
	}
	f, err := os.Create("/Users/dennis/Sandbox/wasmbndg/src/lib.rs")
	var w io.Writer
	if err == nil {
		defer f.Close()
		w = io.MultiWriter(os.Stdout, f)
	} else {
		w = os.Stdout
	}

	err = tmpl.ExecuteTemplate(w, "lib", &policy)

	is.NoError(err)
}
