// Copyright 2021-2024 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

//go:build confdocs
// +build confdocs

package main

import (
	"bytes"
	_ "embed"
	"errors"
	"flag"
	"fmt"
	"go/ast"
	"go/token"
	"go/types"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"text/template"

	"github.com/fatih/structtag"
	"github.com/mattn/go-isatty"
	"go.elastic.co/ecszap"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"golang.org/x/tools/go/packages"
)

const (
	interfacePackage   = "github.com/cerbos/cerbos/internal/config"
	interfaceName      = "Section"
	defaultLogLevel    = "ERROR"
	keyRequired        = "required"
	keyOptional        = "optional"
	optionExampleValue = "example"
	optionIgnore       = "ignore"
)

//go:embed generator.go.tmpl
var templateText string

var (
	errInterfaceNotFound = errors.New("interface not found")
	errTagNotExists      = errors.New("yaml tag does not exist")
	descRegex            = regexp.MustCompile(`\+desc=(.+)`)
)

var (
	rootDir    = flag.String("rootDir", ".", "Root directory to scan")
	outputFile = flag.String("outFile", "docs/modules/configuration/partials/fullconfiguration.adoc", "Path to output the content")

	logger      *zap.SugaredLogger
	excludeObjs = map[string]struct{}{"CompilationUnit": {}, "Section": {}}
)

type StructInfo struct {
	Pkg           string
	Name          string
	Documentation string
	Fields        []FieldInfo
}

type FieldInfo struct {
	Name          string
	Documentation string
	Tag           string
	Fields        []FieldInfo
	Array         bool
}

type TagInfo struct {
	DefaultValue string
	Name         string
	Ignore       bool
	Required     bool
}

type Output struct {
	Imports  map[string]string
	Sections map[string]string
	File     string
}

func init() {
	if envLevel := os.Getenv("CONFDOCS_LOG_LEVEL"); envLevel != "" {
		doInitLogging(envLevel)
		return
	}
	doInitLogging(defaultLogLevel)
}

func main() {
	flag.Parse()
	absRootDir, err := filepath.Abs(*rootDir)
	if err != nil {
		logger.Fatalf("Failed to find absolute path to %q: %v", *rootDir, err)
	}

	absOutputFile, err := filepath.Abs(*outputFile)
	if err != nil {
		logger.Fatalf("Failed to find absolute path to %q: %v", *outputFile, err)
	}

	pkgs, err := loadPackages(absRootDir)
	if err != nil {
		logger.Fatalf("failed to load packages: %v", err)
	}

	iface, err := findInterfaceDef(pkgs)
	if err != nil {
		logger.Fatalf("failed to find %s.%s: %v", interfacePackage, interfaceName, err)
	}

	structs := findIfaceImplementors(iface, pkgs)

	output := Output{
		File:     absOutputFile,
		Imports:  make(map[string]string),
		Sections: make(map[string]string),
	}
	for i, s := range structs {
		imp := fmt.Sprintf("c%d", i)
		output.Imports[imp] = s.Pkg
		output.Sections[fmt.Sprintf("%s.%s", imp, s.Name)] = genDocs(s)
	}

	tmpl, err := template.New("generator.go").Parse(templateText)
	if err != nil {
		logger.Fatalf("failed to parse template: %v", err)
	}

	if err := tmpl.Execute(os.Stdout, output); err != nil {
		logger.Fatalf("failed to render template: %v", err)
	}
}

func loadPackages(pkgDir string) ([]*packages.Package, error) {
	cfg := &packages.Config{
		Mode: packages.NeedTypes | packages.NeedTypesInfo | packages.NeedSyntax,
		Dir:  pkgDir,
		Logf: logger.Infof,
	}

	return packages.Load(cfg, "./...")
}

func findInterfaceDef(pkgs []*packages.Package) (*types.Interface, error) {
	for _, pkg := range pkgs {
		if obj := pkg.Types.Scope().Lookup(interfaceName); obj != nil {
			return obj.Type().Underlying().(*types.Interface), nil
		}
	}

	return nil, errInterfaceNotFound
}

func findIfaceImplementors(iface *types.Interface, pkgs []*packages.Package) []*StructInfo {
	var impls []*StructInfo

	// `traversedObjMap` is used to store fields against the object FQN as we traverse the AST.
	// This allows us to assign fields for non-local embedded structs on the fly by constructing
	// the FQN and retrieving the fields from the map.
	// We don't have to wait until traversal completion as embedded structs should already be available
	// in the map given the depth-first traversal order of the AST.
	traversedObjMap := make(map[string][]FieldInfo)

	for _, pkg := range pkgs {
		scope := pkg.Types.Scope()
		for _, name := range scope.Names() {
			obj := scope.Lookup(name)
			if implementsIface(iface, obj) {
				if _, ok := excludeObjs[obj.Name()]; ok {
					continue
				}

				if si := inspect(pkg, obj, traversedObjMap); si != nil {
					impls = append(impls, si)

					traversedObjMap[pkg.ID+"."+obj.Name()] = si.Fields
				}
			}
		}
	}

	return impls
}

func implementsIface(iface *types.Interface, obj types.Object) bool {
	if obj == nil || !obj.Exported() {
		return false
	}

	t := obj.Type()
	if types.Implements(t, iface) {
		return true
	}

	ptr := types.NewPointer(t)
	if ptr != nil && types.Implements(ptr, iface) {
		return true
	}

	return false
}

func inspect(pkg *packages.Package, obj types.Object, traversedObjMap map[string][]FieldInfo) *StructInfo {
	ts, cg := find(pkg.Syntax, obj.Name())
	if ts == nil {
		logger.Fatalf("Failed to find object named %q", obj.Name())
		return nil
	}

	doc, _ := parseDescMarker(cg)
	si := &StructInfo{Pkg: pkg.ID, Name: ts.Name.Name, Documentation: doc}
	si.Fields = inspectStruct(ts.Type, pkg.TypesInfo, traversedObjMap)

	return si
}

func find(files []*ast.File, objName string) (*ast.TypeSpec, *ast.CommentGroup) {
	f := &finder{objName: objName}
	for _, file := range files {
		ast.Walk(f, file)
		if f.typeSpec != nil {
			break
		}
	}

	return f.typeSpec, f.commentGroup
}

func inspectStruct(node ast.Expr, info *types.Info, traversedObjMap map[string][]FieldInfo) []FieldInfo {
	var fields []FieldInfo
	switch t := node.(type) {
	case *ast.StructType:
		for _, f := range t.Fields.List {
			if len(f.Names) == 0 {
				switch i := f.Type.(type) {
				case *ast.Ident:
					ts, ok := i.Obj.Decl.(*ast.TypeSpec)
					if ok {
						st, ok := ts.Type.(*ast.StructType)
						if ok {
							fields = inspectStruct(st, info, traversedObjMap)
							continue
						}
					}
				case *ast.SelectorExpr:
					// Handle non-local embedded structs
					if obj, ok := info.Uses[i.Sel]; ok {
						if id, ok := i.X.(*ast.Ident); ok {
							if obj.Pkg().Name() == id.Name && obj.Name() == i.Sel.Name {
								if embeddedFields, ok := traversedObjMap[obj.Pkg().Path()+"."+obj.Name()]; ok {
									fields = append(fields, embeddedFields...)
								}
							}
						}
					}
					continue
				}
			}

			fi := FieldInfo{Name: f.Names[0].Name, Documentation: strings.TrimSpace(f.Doc.Text())}
			if f.Tag != nil {
				fi.Tag = f.Tag.Value
			}

			if _, ok := f.Type.(*ast.ArrayType); ok {
				fi.Array = true
			}

			fi.Fields = inspectStruct(f.Type, info, traversedObjMap)

			fields = append(fields, fi)
		}
	case *ast.StarExpr:
		return inspectStruct(t.X, info, traversedObjMap)
	case *ast.Ident:
		if t.Obj != nil && t.Obj.Kind == ast.Typ {
			if ts, ok := t.Obj.Decl.(*ast.TypeSpec); ok {
				return inspectStruct(ts.Type, info, traversedObjMap)
			}
		}
	case *ast.ArrayType:
		return inspectStruct(t.Elt, info, traversedObjMap)
	}

	sort.Slice(fields, func(i, j int) bool {
		return fields[i].Name < fields[j].Name
	})
	return fields
}

func genDocs(si *StructInfo) string {
	buf := new(bytes.Buffer)
	if err := doGenDocs(buf, si, 0); err != nil {
		logger.Fatalw("Failed to generate docs", "pkg", si.Pkg, "struct", si.Name, "error", err)
	}

	return buf.String()
}

func doGenDocs(out io.Writer, si *StructInfo, indent int) error {
	if si.Documentation != "" {
		if err := indentf(out, indent, "# %s\n", si.Documentation); err != nil {
			return err
		}
	}

	return walkFields(out, si.Fields, indent)
}

func walkFields(out io.Writer, fields []FieldInfo, indent int) error {
	for _, field := range fields {
		name := field.Name
		defaultValue := ""
		docs := ""

		tag, err := parseTag(field.Tag)
		if err != nil {
			return fmt.Errorf("failed to parse tags: %w", err)
		}

		if tag != nil {
			if tag.Ignore {
				continue
			}
			if tag.Name != "" {
				name = tag.Name
			}
			if tag.DefaultValue != "" {
				defaultValue = tag.DefaultValue
			}
			if tag.Required {
				docs = "Required. "
			}
		}

		if field.Documentation != "" {
			docs = fmt.Sprintf("%s%s", docs, field.Documentation)
		}

		if docs != "" {
			docs = fmt.Sprintf("# %s", docs)
		}

		if field.Fields != nil {
			if err := indentf(out, indent, "%s: %s\n", name, docs); err != nil {
				return err
			}

			if field.Array {
				if err := indentf(out, indent+1, "- \n"); err != nil {
					return err
				}

				if err := walkFields(out, field.Fields, indent+2); err != nil {
					return err
				}
				continue
			}

			if err := walkFields(out, field.Fields, indent+1); err != nil {
				return err
			}

			continue
		}

		if defaultValue == "" {
			return fmt.Errorf("field %q lacks a default value, specify one with `conf:\",example=...\"`", name)
		}

		if err := indentf(out, indent, "%s: %s %s\n", name, defaultValue, docs); err != nil {
			return err
		}
	}

	return nil
}

func indentf(out io.Writer, n int, format string, args ...any) error {
	if _, err := fmt.Fprint(out, strings.Repeat("  ", n)); err != nil {
		return err
	}

	_, err := fmt.Fprintf(out, format, args...)
	return err
}

func parseTag(tag string) (*TagInfo, error) {
	if tag == "" {
		return nil, errTagNotExists
	}

	t, err := structtag.Parse(tag[1 : len(tag)-1])
	if err != nil {
		return nil, fmt.Errorf("structtag failed to parse tags: %w", err)
	}

	if t == nil {
		return nil, errTagNotExists
	}

	yamlTag, err := t.Get("yaml")
	if err != nil {
		return nil, errTagNotExists
	}

	ti := &TagInfo{Name: yamlTag.Name}

	if confTag, _ := t.Get("conf"); confTag != nil {
		switch confTag.Name {
		case keyRequired:
			ti.Required = true
		case keyOptional:
			ti.Required = false
		}

		for _, option := range confTag.Options {
			sp := strings.SplitN(option, "=", 2)

			switch sp[0] {
			case optionExampleValue:
				ti.DefaultValue = sp[1]
			case optionIgnore:
				ti.Ignore = true
			}
		}
	}

	return ti, nil
}

func parseDescMarker(cg *ast.CommentGroup) (string, bool) {
	if cg == nil {
		return "", false
	}
	for _, c := range cg.List {
		submatches := descRegex.FindAllStringSubmatch(c.Text, -1)
		if submatches != nil && submatches[0] != nil {
			return submatches[0][1], true
		}
	}

	return "", false
}

type finder struct {
	typeSpec     *ast.TypeSpec
	commentGroup *ast.CommentGroup
	objName      string
}

func (f *finder) Visit(n ast.Node) ast.Visitor {
	switch t := n.(type) {
	case *ast.TypeSpec:
		if t.Name.Name == f.objName {
			f.typeSpec = t
			return nil
		}
	case *ast.GenDecl:
		if t.Tok == token.TYPE && t.Doc != nil && len(t.Specs) > 0 {
			typeSpec, ok := t.Specs[0].(*ast.TypeSpec)
			if ok && typeSpec.Name.Name == f.objName {
				f.commentGroup = t.Doc
			}
		}
	}

	return f
}

func (f finder) findReceiverObj(tpe ast.Expr) *ast.StructType {
	switch t := tpe.(type) {
	case *ast.StarExpr:
		return f.findReceiverObj(t.X)
	case *ast.StructType:
		return t
	case *ast.Ident:
		if t.Obj != nil && t.Obj.Kind == ast.Typ && t.Obj.Name == f.objName {
			if ts, ok := t.Obj.Decl.(*ast.TypeSpec); ok {
				return f.findReceiverObj(ts.Type)
			}
		}
	}
	return nil
}

func doInitLogging(level string) {
	errorPriority := zap.LevelEnablerFunc(func(lvl zapcore.Level) bool {
		return lvl >= zapcore.ErrorLevel
	})

	minLogLevel := zapcore.InfoLevel

	switch strings.ToUpper(level) {
	case "DEBUG":
		minLogLevel = zapcore.DebugLevel
	case "INFO":
		minLogLevel = zapcore.InfoLevel
	case "WARN":
		minLogLevel = zapcore.WarnLevel
	case "ERROR":
		minLogLevel = zapcore.ErrorLevel
	}

	infoPriority := zap.LevelEnablerFunc(func(lvl zapcore.Level) bool {
		return lvl < zapcore.ErrorLevel && lvl >= minLogLevel
	})

	consoleErrors := zapcore.Lock(os.Stderr)
	consoleInfo := zapcore.Lock(os.Stdout)

	encoderConf := ecszap.NewDefaultEncoderConfig().ToZapCoreEncoderConfig()
	var consoleEncoder zapcore.Encoder

	if !isatty.IsTerminal(os.Stdout.Fd()) {
		consoleEncoder = zapcore.NewJSONEncoder(encoderConf)
	} else {
		encoderConf.EncodeLevel = zapcore.CapitalColorLevelEncoder
		consoleEncoder = zapcore.NewConsoleEncoder(encoderConf)
	}

	core := zapcore.NewTee(
		zapcore.NewCore(consoleEncoder, consoleErrors, errorPriority),
		zapcore.NewCore(consoleEncoder, consoleInfo, infoPriority),
	)

	stackTraceEnabler := zap.LevelEnablerFunc(func(lvl zapcore.Level) bool {
		return lvl > zapcore.ErrorLevel
	})
	l := zap.New(core, zap.AddStacktrace(stackTraceEnabler))

	zap.ReplaceGlobals(l.Named("confdocs"))
	zap.RedirectStdLog(l.Named("stdlog"))

	logger = l.Sugar()
}
