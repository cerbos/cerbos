package confdocs

import (
	"fmt"
	"github.com/fatih/color"
	"go.uber.org/zap"
	"text/template"
)

type Engine struct {
	log           *zap.SugaredLogger
	index         Index
	templateFile  string
	getFileNameFn func(pkgPath, structName string) string
	getRootNameFn func(pkgPath string) string
	templ         *template.Template
}

func NewEngine(logger *zap.SugaredLogger, index Index, templateFile string,
	getFileNameFn func(pkgPath, structName string) string, getRootNameFn func(pkgPath string) string) *Engine {
	return &Engine{
		log:           logger,
		index:         index,
		templateFile:  templateFile,
		getFileNameFn: getFileNameFn,
		getRootNameFn: getRootNameFn,
	}
}

func (e *Engine) Run() error {
	var err error

	e.templ, err = template.New("docs").Parse(e.templateFile)
	if err != nil {
		return err
	}

	for _, str := range e.index {
		color.Set(color.FgRed)
		fmt.Printf("%s\n", e.getFileNameFn(str.PkgPath, str.Name))
		color.Unset()
		color.Set(color.FgGreen)
		e.walk(str)
		color.Unset()
	}

	return nil
}

func (e *Engine) walk(s *Struct) {
	e.doWalk(s.Fields, "")
}

func (e *Engine) doWalk(fields []*StructField, prefix string) {
	for _, field := range fields {
		if field.Fields != nil {
			fmt.Printf("%s%s: %s %s\n", prefix, field.Name, field.Tags, field.Docs)
			e.doWalk(field.Fields, fmt.Sprintf("%s    ", prefix))
		} else {
			fmt.Printf("%s%s %s %s\n", prefix, field.Name, field.Tags, field.Docs)
		}
	}
}
