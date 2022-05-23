package wasm

import (
	"io/fs"
	"github.com/cerbos/cerbos/internal/schema"
	"context"
	"github.com/cerbos/cerbos/internal/compile"
	"github.com/cerbos/cerbos/internal/namer"
	"errors"
	"github.com/cerbos/cerbos/internal/storage"
	"os"
	"path/filepath"
	_ "embed"
	"text/template"
	"embed"
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
	ErrPolicyNotFound        = errors.New("policy not found")
)

type Builder struct {
	store     storage.Store
	outputDir string
	workDir   string
	tmpl      *template.Template
}

//go:embed templates/*.tmpl
var templatesFS embed.FS

func NewBuilder(store storage.Store, workDir, outputDir string) (*Builder, error) {
	tmpl, err := template.ParseFS(templatesFS, "templates/*.tmpl")
	if err != nil {
		return nil, err
	}

	return &Builder{
		store:     store,
		workDir:   workDir,
		outputDir: outputDir,
		tmpl:      tmpl,
	}, nil
}

func (b *Builder) FromPolicy(ctx context.Context, resource, version, scope string) (*Policy, error) {
	schemaConf := schema.NewConf(schema.EnforcementReject)
	schemaMgr := schema.NewFromConf(ctx, b.store, schemaConf)
	manager := compile.NewManagerFromDefaultConf(ctx, b.store, schemaMgr)

	rps, err := manager.Get(ctx, namer.ResourcePolicyModuleID(resource, version, scope))
	if err != nil {
		return nil, err
	}
	if rps == nil {
		return nil, ErrPolicyNotFound
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
	policy, err := NewPolicy(ps, rs, rp)
	if err != nil {
		return nil, err
	}
	srcDir, err := createRustProject(b.workDir)
	if err != nil {
		return nil, err
	}
	file, err := os.Create(filepath.Join(srcDir, "lib.rs"))
	if err != nil {
		return nil, err
	}
	defer file.Close()

	err = b.tmpl.ExecuteTemplate(file, "lib", policy)
	if err != nil {
		return nil, err
	}
	return policy, nil
}

var (
	//go:embed files/Cargo.lock
	cargoLock []byte
	//go:embed files/Cargo.toml
	cargoToml []byte
)

func createRustProject(workDir string) (string, error) {
	temp, err := os.CreateTemp(workDir, "cerbos*")
	if err != nil {
		return "", err
	}

	srcDir := filepath.Join(temp.Name(), "src")
	err = os.Mkdir(srcDir, 0750)
	if err != nil {
		return "", err
	}

	err = os.WriteFile(filepath.Join(temp.Name(), "Cargo.lock"), cargoLock, 0750)
	if err != nil {
		return "", err
	}

	err = os.WriteFile(filepath.Join(temp.Name(), "Cargo.toml"), cargoToml, 0750)
	if err != nil {
		return "", err
	}

	return srcDir, nil
}
