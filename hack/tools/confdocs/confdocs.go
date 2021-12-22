// Copyright 2021 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	_ "embed"
	"errors"
	"fmt"
	"go/ast"
	"go/token"
	"go/types"
	"io"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"

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
	internalPkgPrefix  = "github.com/cerbos/cerbos/internal/"
	confKeyConstName   = "confKey"
	defaultLogLevel    = "ERROR"
	keyRequired        = "required"
	keyOptional        = "optional"
	optionDefaultValue = "defaultValue"
	optionIgnore       = "ignore"
)

var (
	errTagNotExists = errors.New("yaml tag does not exist")
	r               = regexp.MustCompile(`\+sectionKey=([a-zA-Z.]+)`)
)

type StructInfo struct {
	Pkg           string      `json:"pkg"`
	SectionKey    string      `json:"section_key"`
	Name          string      `json:"name"`
	Documentation string      `json:"documentation"`
	Fields        []FieldInfo `json:"fields"`
}

type FieldInfo struct {
	Name          string      `json:"name"`
	Documentation string      `json:"documentation"`
	Tag           string      `json:"tags"`
	Fields        []FieldInfo `json:"fields"`
}

type TagInfo struct {
	DefaultValue string
	Name         string
	Ignore       bool
	Required     bool
}

var logger *zap.SugaredLogger

func init() {
	if envLevel := os.Getenv("CONFDOCS_LOG_LEVEL"); envLevel != "" {
		doInitLogging(envLevel)
		return
	}
	doInitLogging(defaultLogLevel)
}

func main() {
	partialsDir, err := getPartialsDir()
	if err != nil {
		logger.Fatalf("failed to get partials directory: %v", err)
	}

	pkgsDir, err := getPackagesDir()
	if err != nil {
		logger.Fatalf("failed to get packages directory: %v", err)
	}

	pkgs, err := loadCurrPackage(pkgsDir)
	if err != nil {
		logger.Fatalf("failed to load package: %v", err)
	}

	iface, err := findInterfaceDef()
	if err != nil {
		logger.Fatalf("failed to find %s.%s: %v", interfacePackage, interfaceName, err)
	}

	impls := findIfaceImplementors(iface, pkgs)
	for _, imp := range impls {
		if err := genDocs(partialsDir, imp); err != nil {
			logger.Fatalf("Failed to generate docs for %s.%s: %v", imp.Pkg, imp.Name, err)
		}
	}
}

func getPackagesDir() (string, error) {
	cwd, err := os.Getwd()
	if err != nil {
		return "", fmt.Errorf("failed to get working directory: %v", err)
	}

	dir, err := filepath.Abs(cwd)
	if err != nil {
		return "", fmt.Errorf("failed to get absolute path: %v", err)
	}

	return dir, nil
}

func getPartialsDir() (string, error) {
	_, currFile, _, ok := runtime.Caller(0)
	if !ok {
		return "", fmt.Errorf("failed to get working directory")
	}

	return filepath.Join(filepath.Dir(currFile), "..", "..", "..", "docs/modules/configuration/partials"), nil
}

func loadCurrPackage(pkgDir string) ([]*packages.Package, error) {
	pkgFile, ok := os.LookupEnv("GOFILE")
	if !ok || pkgFile == "" {
		return nil, fmt.Errorf("unable to determine GOFILE")
	}

	cfg := &packages.Config{
		Mode: packages.NeedTypes | packages.NeedTypesInfo | packages.NeedSyntax,
		Logf: logger.Infof,
	}

	return packages.Load(cfg, fmt.Sprintf("file=%s", filepath.Join(pkgDir, pkgFile)))
}

func findInterfaceDef() (*types.Interface, error) {
	cfg := &packages.Config{
		Mode: packages.NeedTypes | packages.NeedTypesInfo,
		Logf: log.Printf,
	}

	pkgs, err := packages.Load(cfg, interfacePackage)
	if err != nil {
		return nil, err
	}

	for _, p := range pkgs {
		if obj := p.Types.Scope().Lookup(interfaceName); obj != nil {
			return obj.Type().Underlying().(*types.Interface), nil
		}
	}

	return nil, nil
}

func findIfaceImplementors(iface *types.Interface, pkgs []*packages.Package) []*StructInfo {
	var impls []*StructInfo

	for _, pkg := range pkgs {
		scope := pkg.Types.Scope()
		for _, name := range scope.Names() {
			obj := scope.Lookup(name)
			if implementsIface(iface, obj) {
				if si := inspect(pkg, obj); si != nil {
					impls = append(impls, si)
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

func inspect(pkg *packages.Package, obj types.Object) *StructInfo {
	ts, vs, cg := find(pkg.Syntax, obj.Name(), confKeyConstName)
	if vs == nil {
		logger.Fatalf("Failed to find constant named %q", confKeyConstName)
	}

	if ts == nil {
		logger.Fatalf("Failed to find object named %q", obj.Name())
	}

	ast.Print(nil, vs)

	var sectionKey = "<MISSING_SECTION_KEY>"
	switch v := vs.Values[0].(type) {
	case *ast.BasicLit:
		sectionKey = strings.Trim(v.Value, "\"")
		break
	}

	var doc = ""
	if cg != nil && cg.List[0] != nil {
		doc = strings.TrimSpace(strings.TrimPrefix(cg.List[0].Text, "//"))
	}
	si := &StructInfo{Pkg: pkg.ID, SectionKey: sectionKey, Name: ts.Name.Name, Documentation: doc}
	si.Fields = inspectStruct(ts.Type)
	var ok bool
	si.SectionKey, ok = parseSectionKey(cg)
	if !ok {
		logger.Debug()
	}

	return si
}

func find(files []*ast.File, objName, constName string) (*ast.TypeSpec, *ast.ValueSpec, *ast.CommentGroup) {
	f := &finder{objName: objName, constName: constName}
	for _, file := range files {
		ast.Walk(f, file)
		if f.typeSpec != nil && f.constSpec != nil {
			break
		}
	}

	return f.typeSpec, f.constSpec, f.commentGroup
}

func inspectStruct(node ast.Expr) []FieldInfo {
	var fields []FieldInfo
	switch t := node.(type) {
	case *ast.StructType:
		for _, f := range t.Fields.List {
			if len(f.Names) == 0 {
				// TODO Handle Embedded struct
				continue
			}

			fi := FieldInfo{Name: f.Names[0].Name, Documentation: strings.TrimSpace(f.Doc.Text())}
			if f.Tag != nil {
				fi.Tag = f.Tag.Value
			}
			fi.Fields = inspectStruct(f.Type)

			fields = append(fields, fi)
		}
	case *ast.StarExpr:
		return inspectStruct(t.X)
	case *ast.Ident:
		if t.Obj != nil && t.Obj.Kind == ast.Typ {
			if ts, ok := t.Obj.Decl.(*ast.TypeSpec); ok {
				return inspectStruct(ts.Type)
			}
		}
	}

	return fields
}

func genDocs(partialsDir string, si *StructInfo) error {
	dottedPkg := strings.ReplaceAll(strings.TrimPrefix(si.Pkg, internalPkgPrefix), "/", ".")
	fileName := filepath.Join(partialsDir, fmt.Sprintf("%s.%s.adoc", strings.ToLower(si.Name), dottedPkg))

	buf := new(bytes.Buffer)
	buf.WriteString(fileName)
	buf.WriteString("\n")

	if err := doGenDocs(buf, si, 0); err != nil {
		return err
	}

	// TODO write to file instead of stdout
	fmt.Println(buf.String())
	fmt.Printf("%s\n", strings.Repeat("-", 80))
	return nil
}

func doGenDocs(out io.Writer, si *StructInfo, indent int) error {
	docs := ""
	if si.Documentation != "" {
		docs = fmt.Sprintf("# %s", si.Documentation)
	}

	if err := indentf(out, indent, "%s: %s\n", si.SectionKey, docs); err != nil {
		return err
	}

	return walkFields(out, si.Fields, indent+1)
}

func walkFields(out io.Writer, fields []FieldInfo, indent int) error {
	for _, field := range fields {
		name := field.Name
		defaultValue := "<DEFAULT_VALUE_NOT_SET>"
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

			if err := walkFields(out, field.Fields, indent+1); err != nil {
				return err
			}

			continue
		}

		if err := indentf(out, indent, "%s: %s %s\n", name, defaultValue, docs); err != nil {
			return err
		}
	}

	return nil
}

func indentf(out io.Writer, n int, format string, args ...interface{}) error {
	if _, err := fmt.Fprint(out, strings.Repeat("  ", n)); err != nil {
		return err
	}

	_, err := fmt.Fprintf(out, format, args...)
	return err
}

func parseTag(tag string) (*TagInfo, error) {
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
			case optionDefaultValue:
				ti.DefaultValue = sp[1]
			case optionIgnore:
				ti.Ignore = true
			}
		}
	}

	return ti, nil
}

func parseSectionKey(cg *ast.CommentGroup) (string, bool) {
	for _, c := range cg.List {
		submatches := r.FindAllStringSubmatch(c.Text, -1)
		if submatches != nil && submatches[0] != nil {
			return submatches[0][1], true
		}
	}

	return "", false
}

type finder struct {
	objName      string
	constName    string
	typeSpec     *ast.TypeSpec
	constSpec    *ast.ValueSpec
	commentGroup *ast.CommentGroup
}

func (f *finder) Visit(n ast.Node) ast.Visitor {
	switch t := n.(type) {
	case *ast.TypeSpec:
		if t.Name.Name == f.objName {
			f.typeSpec = t
		}
	case *ast.GenDecl:
		if t.Tok == token.CONST && len(t.Specs) > 0 {
			vs, ok := t.Specs[0].(*ast.ValueSpec)
			if ok {
				if vs.Names[0].Name == f.constName || vs.Names[0].Name == strings.Title(f.constName) {
					f.constSpec = vs
				}
			}
		} else if t.Tok == token.TYPE && t.Doc != nil && len(t.Specs) > 0 {
			typeSpec, ok := t.Specs[0].(*ast.TypeSpec)
			if ok && typeSpec.Name.Name == f.objName {
				f.commentGroup = t.Doc
			}
		}
	}

	if f.typeSpec != nil && f.constSpec != nil {
		return nil
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
