// Copyright 2021-2026 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

//go:build loadtest

package main

import (
	"embed"
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"text/template"

	"github.com/alecthomas/kong"
)

const (
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

	renderers := make([]renderFunc, 0, len(tmplOutConf))
	for tmplDir, outDir := range tmplOutConf {
		r, err := createRenderer(tmplDir, filepath.Join(c.Out, outDir))
		if err != nil {
			return fmt.Errorf("failed to create renderer for %q: %w", tmplDir, err)
		}

		renderers = append(renderers, r)
	}

	for i := 0; i < c.Count; i++ {
		i := i
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

	return c.buildReqIndex()
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

func (c *cmd) buildReqIndex() error {
	requests, err := fs.Glob(fsys, filepath.Join(templatesDir, requestsDir, "*.tpl"))
	if err != nil {
		return fmt.Errorf("failed to glob request templates: %w", err)
	}

	index := make(map[string][]string)
	for _, req := range requests {
		fn := strings.TrimSuffix(filepath.Base(req), ".json.tpl")
		fileList := make([]string, c.Count)
		for i := 0; i < c.Count; i++ {
			fileList[i] = fmt.Sprintf("%s_%05d.json", fn, i)
		}

		index[fn] = fileList
	}

	idxFile := filepath.Join(c.Out, tmplOutConf[requestsDir], "index.json")
	f, err := os.Create(idxFile)
	if err != nil {
		return fmt.Errorf("failed to create %q: %w", idxFile, err)
	}

	defer f.Close()

	m := json.NewEncoder(f)
	return m.Encode(index)
}
