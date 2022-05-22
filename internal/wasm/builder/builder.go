package builder

import (
	"github.com/cerbos/cerbos/internal/storage/disk"
	"io/fs"
	"github.com/cerbos/cerbos/internal/schema"
	"context"
	"github.com/cerbos/cerbos/internal/compile"
	"github.com/cerbos/cerbos/internal/namer"
	"errors"
)

type Config struct {
	Store     *disk.Store
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

func FromPolicy(ctx context.Context, c *Config) error {
	schemaConf := schema.NewConf(schema.EnforcementReject)
	schemaMgr := schema.NewFromConf(ctx, c.Store, schemaConf)
	manager := compile.NewManagerFromDefaultConf(ctx, c.Store, schemaMgr)

	rps, err := manager.Get(ctx, namer.ResourcePolicyModuleID(c.Resource, c.Version, c.Scope))
	if err != nil {
		return err
	}
	rp := rps.GetResourcePolicy()
	if rp == nil {
		return ErrUnsupportedPolicy
	}
	if rp.Schemas == nil || rp.Schemas.PrincipalSchema == nil || rp.Schemas.ResourceSchema == nil {
		return ErrPolicyMustHaveSchemas
	}
	return nil
}
