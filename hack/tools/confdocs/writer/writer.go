// Copyright 2021 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package writer

import (
	"bytes"
	"fmt"
	"github.com/cerbos/cerbos/hack/tools/confdocs/indexer"
	"go.uber.org/zap"
	"io"
	"strings"
)

const tabString = "  "

type Writer struct {
	Options
}

type Options struct {
	Log               *zap.SugaredLogger
	Index             indexer.Index
	IgnoreTabsForPkgs []string
	GetFileNameFn     func(pkgPath, structName string) string
}

func New(options Options) *Writer {
	return &Writer{
		Options: options,
	}
}

// Run the writer with the given index of struct from options and returns a map of file names and file contents.
func (w *Writer) Run() (map[string]*bytes.Buffer, error) {
	var data = make(map[string]*bytes.Buffer)

	for _, str := range w.Index {
		fileName := w.GetFileNameFn(str.PkgPath, str.Name)

		split := strings.Split(fileName, ".")
		parent := split[len(split)-2]
		pkg := split[len(split)-3]
		extraTabs := len(split) - 3

		for _, p := range w.IgnoreTabsForPkgs {
			if p == pkg {
				extraTabs = extraTabs - 1
			}
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

// walk over the given struct and writes the docs to writer.
func (w *Writer) walk(s *indexer.Struct, parent string, extraTabs int, writer io.Writer) error {
	tabs := strings.Builder{}
	for i := 0; i < extraTabs; i++ {
		_, err := tabs.WriteString(tabString)
		if err != nil {
			return fmt.Errorf("failed to generate extra tabs: %w", err)
		}
	}

	docs := ""
	if s.Docs != "" {
		docs = fmt.Sprintf("# %s", s.Docs)
	}

	_, err := fmt.Fprintf(writer, "%s%s: %s\n", tabs.String(), parent, docs)
	if err != nil {
		return fmt.Errorf("failed to prepend file with parent name: %w", err)
	}

	return w.doWalk(s.Fields, writer, fmt.Sprintf("%s%s", tabString, tabs.String()))
}

func (w *Writer) doWalk(fields []*indexer.StructField, writer io.Writer, prefix string) error {
	for _, field := range fields {
		name := field.Name
		defaultValue := "<DEFAULT_VALUE_NOT_SET>"
		docs := ""

		if field.TagsData != nil {
			if field.TagsData.Ignore {
				continue
			}
			name = field.TagsData.Name
			if field.TagsData.ConfOptions.DefaultValue != "" {
				defaultValue = field.TagsData.DefaultValue
			}

			if field.TagsData.Required {
				docs = "Required. "
			}
		}

		if field.Docs != "" {
			docs = fmt.Sprintf("%s%s", docs, field.Docs)
		}

		if docs != "" {
			docs = fmt.Sprintf("# %s", docs)
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
