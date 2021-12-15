package writer

import (
	"bytes"
	"fmt"
	"github.com/cerbos/cerbos/hack/tools/confdocs/indexer"
	"go.uber.org/zap"
	"io"
	"strings"
	"text/template"
)

const tabString = "  "

type Writer struct {
	Options
	templ *template.Template
}

type Options struct {
	Log           *zap.SugaredLogger
	Index         indexer.Index
	TemplateFile  string
	GetFileNameFn func(pkgPath, structName string) string
}

func New(options Options) *Writer {
	return &Writer{
		Options: options,
	}
}

func (w *Writer) Run() (map[string]*bytes.Buffer, error) {
	var err error
	var data = make(map[string]*bytes.Buffer)

	w.templ, err = template.New("docs").Parse(w.TemplateFile)
	if err != nil {
		return nil, err
	}

	for _, str := range w.Index {
		fileName := w.GetFileNameFn(str.PkgPath, str.Name)

		split := strings.Split(fileName, ".")
		parent := split[len(split)-2]
		extraTabs := len(split) - 3

		if parent == "tracing" {
			extraTabs = 0 // "tracing" is a special case due to it being in a sub-package but not in a sub-config.
		}

		var buf bytes.Buffer
		err := w.walk(str, parent, extraTabs, &buf)
		if err != nil {
			return nil, err
		}

		data[fileName] = &buf
	}

	return data, nil
}

func (w *Writer) walk(s *indexer.Struct, parent string, extraTabs int, writer io.Writer) error {
	tabs := strings.Builder{}
	for i := 0; i < extraTabs; i++ {
		_, err := tabs.WriteString(tabString)
		if err != nil {
			return fmt.Errorf("failed to generate extra tabs: %w", err)
		}
	}

	_, err := fmt.Fprintf(writer, "%s%s:\n", tabs.String(), parent)
	if err != nil {
		return fmt.Errorf("failed to prepend file with parent name: %w", err)
	}

	return w.doWalk(s.Fields, writer, fmt.Sprintf("%s%s", tabString, tabs.String()))
}

func (w *Writer) doWalk(fields []*indexer.StructField, writer io.Writer, prefix string) error {
	for _, field := range fields {
		name := field.Name
		defaultValue := "<DEFAULT_VALUE_NOT_SET>"
		if field.TagsData != nil {
			if field.TagsData.Ignore {
				continue
			}
			name = field.TagsData.Name
			if field.TagsData.ConfOptions.DefaultValue != "" {
				defaultValue = field.TagsData.DefaultValue
			}
		}

		docs := ""
		if field.Docs != "" {
			docs = fmt.Sprintf("# %s", field.Docs)
		}

		if field.Fields != nil {
			_, err := fmt.Fprintf(writer, "%s%s: %s\n", prefix, name, docs)
			if err != nil {
				return err
			}
			err = w.doWalk(field.Fields, writer, fmt.Sprintf("%s%s", prefix, tabString))
			if err != nil {
				return err
			}
		} else {
			_, err := fmt.Fprintf(writer, "%s%s: %s %s\n", prefix, name, defaultValue, docs)
			if err != nil {
				return err
			}
		}
	}
	return nil
}
