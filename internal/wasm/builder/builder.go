package builder

import (
	"io/fs"
	"github.com/cerbos/cerbos/internal/schema"
	"context"
	"github.com/cerbos/cerbos/internal/compile"
	"github.com/cerbos/cerbos/internal/namer"
	"errors"
	"github.com/cerbos/cerbos/internal/wasm"
	"github.com/cerbos/cerbos/internal/storage"
)

type Config struct {
	Store     storage.Store
	OutputDir string
	Version   string
	Resource  string
	Scope     string
	Target    struct {
		Os   string
		Arch string
	}
	WorkDirFS fs.FS
}

var (
	ErrUnsupportedPolicy     = errors.New("unsupported policy type")
	ErrPolicyMustHaveSchemas = errors.New("policy must have schemas")
)

type Builder struct {
	store     storage.Store
	outputDir fs.FS
	workDirFS fs.FS
}

func NewBuilder(store storage.Store, workDir, outputDir fs.FS) *Builder {
	return &Builder{
		store:     store,
		workDirFS: workDir,
		outputDir: outputDir,
	}
}
func (b *Builder) FromPolicy(ctx context.Context, resource, version, scope string) (*wasm.Policy, error) {
	schemaConf := schema.NewConf(schema.EnforcementReject)
	schemaMgr := schema.NewFromConf(ctx, b.store, schemaConf)
	manager := compile.NewManagerFromDefaultConf(ctx, b.store, schemaMgr)

	rps, err := manager.Get(ctx, namer.ResourcePolicyModuleID(resource, version, scope))
	if err != nil {
		return nil, err
	}
	rp := rps.GetResourcePolicy()
	if rp == nil {
		return nil, ErrUnsupportedPolicy
	}
	if rp.Schemas == nil || rp.Schemas.PrincipalSchema == nil || rp.Schemas.ResourceSchema == nil {
		return nil, ErrPolicyMustHaveSchemas
	}

	ps, err := schema.LoadSchemaFromStore(ctx, rp.Schemas.PrincipalSchema.Ref, b.store)
	if err != nil {
		return nil, err
	}
	rs, err := schema.LoadSchemaFromStore(ctx, rp.Schemas.ResourceSchema.Ref, b.store)
	if err != nil {
		return nil, err
	}
	policy, err := wasm.NewPolicy(ps, rs, rp)
	if err != nil {
		return nil, err
	}

	return policy, nil
}
