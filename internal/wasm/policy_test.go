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

func mkCompiler(t *testing.T) (*compile.Manager, schema.Loader) {
	t.Helper()

	dir := pathToDir(t, "store")

	ctx, cancelFunc := context.WithCancel(context.Background())
	t.Cleanup(cancelFunc)

	store, err := disk.NewStore(ctx, &disk.Conf{Directory: dir})
	require.NoError(t, err)

	schemaConf := schema.NewConf(schema.EnforcementReject)
	schemaMgr := schema.NewFromConf(ctx, store, schemaConf)

	return compile.NewManagerFromDefaultConf(ctx, store, schemaMgr), store
}

func TestNewCompiler(t *testing.T) {
	is := require.New(t)

	compiler, _ := mkCompiler(t)
	is.NotNil(compiler)
}

//func TestGenPolicy(t *testing.T) {
//	resource, policyVer, scope := "leave_request", "staging", ""
//	resourceModID := namer.ResourcePolicyModuleID(resource, policyVer, scope)
//	compiler, schLdr := mkCompiler(t)
//	ctx := context.Background()
//	rps, err := compiler.Get(ctx, resourceModID)
//	is := require.New(t)
//	is.NoError(err)
//	is.NotNil(rps)
//	rp := rps.GetResourcePolicy()
//	is.NotNil(rp)
//
//	reader, err := schLdr.LoadSchema(ctx, rp.Schemas.ResourceSchema.Ref)
//	is.NoError(err)
//	is.NotNil(schema)
//	rProps, err := convert(io.Re)
//	tmpl, err := template.ParseFS(templatesFS, "templates/*.tmpl")
//	is.NoError(err)
//
//	schema, err = schLdr.LoadSchema(ctx, rp.Schemas.PrincipalSchema.Ref)
//	is.NoError(err)
//	is.NotNil(schema)
//	props, err := convert(s)
//	is.NoError(err)
//	err = tmpl.ExecuteTemplate(os.Stdout, "lib", struct{ Resource []*Field }{props})
//	is.NoError(err)
//}
