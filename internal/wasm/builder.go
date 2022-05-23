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
	"text/template"
	"embed"
	"os/exec"
	"fmt"
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

var (
	//go:embed files/Cargo.lock
	cargoLock []byte
	//go:embed files/Cargo.toml
	cargoToml []byte
	//go:embed templates/*.tmpl
	templatesFS embed.FS
)

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

func (b *Builder) FromPolicy(ctx context.Context, resource, version, scope, targetOs string) (*Policy, error) {
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
	err = buildRustProject(ctx, filepath.Clean(filepath.Join(srcDir, "..")), targetOs)
	if err != nil {
		return nil, err
	}
	return policy, nil
}

func buildRustProject(ctx context.Context, workDir string, targetOs string) error {
	argv := []string{"build", "--target", targetOs}
	// TODO: Set timeout
	cmd := exec.CommandContext(ctx, "wasm-pack", argv...)
	cmd.Dir = workDir
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to build policy code: %w", err)
	}
	return nil
}

func createRustProject(workDir string) (string, error) {
	temp, err := os.MkdirTemp(workDir, "cerbos*")
	if err != nil {
		return "", err
	}
	srcDir := filepath.Join(temp, "src")
	err = os.Mkdir(srcDir, 0755)
	if err != nil {
		return "", fmt.Errorf("failed to create a \"src\" directory: %w", err)
	}

	err = os.WriteFile(filepath.Join(temp, "Cargo.lock"), cargoLock, 0755)
	if err != nil {
		return "", fmt.Errorf("failed to write Cargo.lock file: %w", err)
	}

	err = os.WriteFile(filepath.Join(temp, "Cargo.toml"), cargoToml, 0755)
	if err != nil {
		return "", fmt.Errorf("failed to write Cargo.toml file: %w", err)
	}

	return srcDir, nil
}
