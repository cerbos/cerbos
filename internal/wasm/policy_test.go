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
	"io"
	"text/template"
	"github.com/cerbos/cerbos/internal/storage"
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

func mkCompiler(ctx context.Context, t *testing.T) (*compile.Manager, storage.Store) {
	t.Helper()

	dir := pathToDir(t, "store")

	ctx, cancelFunc := context.WithCancel(ctx)
	t.Cleanup(cancelFunc)

	store, err := disk.NewStore(ctx, &disk.Conf{Directory: dir})
	require.NoError(t, err)

	schemaConf := schema.NewConf(schema.EnforcementReject)
	schemaMgr := schema.NewFromConf(ctx, store, schemaConf)

	return compile.NewManagerFromDefaultConf(ctx, store, schemaMgr), store
}

func TestNewCompiler(t *testing.T) {
	is := require.New(t)

	compiler, _ := mkCompiler(context.Background(), t)
	is.NotNil(compiler)
}

func TestGenPolicy(t *testing.T) {
	tmpl, err := template.ParseFS(templatesFS, "templates/*.tmpl")

	resource, policyVer, scope := "leave_request", "staging", ""
	resourceModID := namer.ResourcePolicyModuleID(resource, policyVer, scope)
	ctx := context.Background()
	mngr, store := mkCompiler(ctx, t)
	rps, err := mngr.Get(ctx, resourceModID)
	is := require.New(t)
	is.NoError(err)
	is.NotNil(rps)
	rp := rps.GetResourcePolicy()
	is.NotNil(rp)

	rs, err := schema.LoadSchemaFromStore(ctx, rp.Schemas.ResourceSchema.Ref, store)
	is.NoError(err)

	ps, err := schema.LoadSchemaFromStore(ctx, rp.Schemas.ResourceSchema.Ref, store)
	is.NoError(err)

	policy, err := NewPolicy(ps, rs, rp)
	is.NoError(err)

	f, err := os.Create("/Users/dennis/Sandbox/wasmbndg/src/lib.rs")
	var w io.Writer
	if err == nil {
		defer f.Close()
		w = io.MultiWriter(os.Stdout, f)
	} else {
		w = os.Stdout
	}

	err = tmpl.ExecuteTemplate(w, "lib", policy)

	is.NoError(err)
}
