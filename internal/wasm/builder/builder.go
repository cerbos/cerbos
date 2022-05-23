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

func FromPolicy(ctx context.Context, c *Config) (*wasm.Policy, error) {
	schemaConf := schema.NewConf(schema.EnforcementReject)
	schemaMgr := schema.NewFromConf(ctx, c.Store, schemaConf)
	manager := compile.NewManagerFromDefaultConf(ctx, c.Store, schemaMgr)

	rps, err := manager.Get(ctx, namer.ResourcePolicyModuleID(c.Resource, c.Version, c.Scope))
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

	ps, err := schema.LoadSchemaFromStore(ctx, rp.Schemas.PrincipalSchema.Ref, c.Store)
	if err != nil {
		return nil, err
	}
	rs, err := schema.LoadSchemaFromStore(ctx, rp.Schemas.ResourceSchema.Ref, c.Store)
	if err != nil {
		return nil, err
	}
	policy, err := wasm.NewPolicy(ps, rs, rp)
	if err != nil {
		return nil, err
	}

	return policy, nil
}
