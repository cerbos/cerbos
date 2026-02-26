// Copyright 2021-2026 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

//go:build loadtest

package main

import (
	"embed"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"text/template"

	"github.com/alecthomas/kong"
)

const (
	filesDir     = "files"
	policiesDir  = "policies"
	requestsDir  = "requests"
	schemasDir   = "schemas"
	templatesDir = "templates"
)

//go:embed templates
var fsys embed.FS

var tmplOutConf = map[string]string{
	policiesDir: policiesDir,
	schemasDir:  filepath.Join(policiesDir, "_schemas"),
	requestsDir: requestsDir,
}

type cmd struct {
	Out   string `default:"work" help:"Directory to output the generated files" type:"path"`
	Count int    `default:"100" help:"Number of copies to generate from each template"`
	Set   string `default:"classic" help:"Policy template set to use (classic, multitenant)"`
}

type templateArgs struct {
	RequestID string
	N         int
}

func (ta templateArgs) NameMod(n string) string {
	return fmt.Sprintf("%s_%05d", n, ta.N)
}

type renderFunc func(templateArgs) error

func main() {
	ctx := kong.Parse(&cmd{},
		kong.Description("Generate load test data"),
		kong.UsageOnError(),
	)

	ctx.FatalIfErrorf(ctx.Run())
}

func (c *cmd) Run() error {
	if err := prepOutDirs(c.Out); err != nil {
		return err
	}

	if err := copyStaticFiles(c.Set, c.Out); err != nil {
		return err
	}

	renderers := make([]renderFunc, 0, len(tmplOutConf))
	for tmplDir, outDir := range tmplOutConf {
		setTmplDir := filepath.Join(c.Set, tmplDir)
		if !dirExistsInEmbed(setTmplDir) {
			continue
		}

		r, err := createRenderer(setTmplDir, filepath.Join(c.Out, outDir))
		if err != nil {
			return fmt.Errorf("failed to create renderer for %q: %w", setTmplDir, err)
		}

		renderers = append(renderers, r)
	}

	for i := 0; i < c.Count; i++ {
		args := templateArgs{
			N:         i,
			RequestID: fmt.Sprintf("REQ_%05d", i),
		}

		for _, r := range renderers {
			if err := r(args); err != nil {
				return fmt.Errorf("failed to render: %w", err)
			}
		}
	}

	return nil
}

func prepOutDirs(out string) error {
	for _, outDir := range tmplOutConf {
		path := filepath.Join(out, outDir)
		if err := os.RemoveAll(path); err != nil {
			return fmt.Errorf("failed to remove %q: %w", path, err)
		}
	}

	for _, outDir := range tmplOutConf {
		path := filepath.Join(out, outDir)
		//nolint:mnd
		if err := os.MkdirAll(path, 0o755); err != nil {
			return fmt.Errorf("failed to create %q: %w", path, err)
		}
	}

	return nil
}

func dirExistsInEmbed(dir string) bool {
	entries, err := fsys.ReadDir(filepath.Join(templatesDir, dir))
	if err != nil {
		return false
	}

	return len(entries) > 0
}

// copyStaticFiles copies files from templates/<set>/files/ to the output directory.
// It is a no-op if the files/ directory does not exist for the given set.
func copyStaticFiles(set, out string) error {
	filesRoot := filepath.Join(templatesDir, set, filesDir)
	if !dirExistsInEmbed(filepath.Join(set, filesDir)) {
		return nil
	}

	return fs.WalkDir(fsys, filesRoot, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}

		rel, err := filepath.Rel(filesRoot, path)
		if err != nil {
			return err
		}

		dest := filepath.Join(out, rel)

		if d.IsDir() {
			//nolint:mnd
			return os.MkdirAll(dest, 0o755)
		}

		return copyEmbedFile(path, dest)
	})
}

func copyEmbedFile(srcPath, destPath string) error {
	src, err := fsys.Open(srcPath)
	if err != nil {
		return fmt.Errorf("failed to open embedded file %q: %w", srcPath, err)
	}
	defer src.Close()

	dst, err := os.Create(destPath)
	if err != nil {
		return fmt.Errorf("failed to create %q: %w", destPath, err)
	}
	defer dst.Close()

	if _, err := io.Copy(dst, src); err != nil {
		return fmt.Errorf("failed to copy %q to %q: %w", srcPath, destPath, err)
	}

	return nil
}

func createRenderer(tmplDir, outDir string) (renderFunc, error) {
	subFS, err := fs.Sub(fsys, filepath.Join(templatesDir, tmplDir))
	if err != nil {
		return nil, fmt.Errorf("unable to descend into %s: %w", tmplDir, err)
	}

	tmpl, err := template.ParseFS(subFS, "*.tpl")
	if err != nil {
		return nil, fmt.Errorf("failed to parse templates from %s: %w", tmplDir, err)
	}

	return mkRenderFunc(outDir, tmpl), nil
}

func mkRenderFunc(out string, tmpl *template.Template) renderFunc {
	templates := tmpl.Templates()
	fileMap := make(map[string]string, len(templates))

	for _, t := range templates {
		name := t.Name()
		fileName := strings.TrimSuffix(name, ".tpl")
		ext := filepath.Ext(fileName)
		fileMap[name] = filepath.Join(out, strings.TrimSuffix(fileName, ext)+"_%05d"+ext)
	}

	return func(args templateArgs) error {
		for _, t := range templates {
			fn := fmt.Sprintf(fileMap[t.Name()], args.N)
			if err := renderFile(fn, t, args); err != nil {
				return fmt.Errorf("failed to render %q:%w", fn, err)
			}
		}

		return nil
	}
}

func renderFile(fileName string, tmpl *template.Template, args templateArgs) error {
	f, err := os.Create(fileName)
	if err != nil {
		return err
	}

	defer f.Close()

	return tmpl.Execute(f, args)
}
