// Copyright 2021 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package test

import (
	"encoding/base64"
	"fmt"
	"io/ioutil"
	"testing"
	"text/template"
)

// TemplateFuncs contains structs (and functions) used in templates.
type TemplateFuncs struct {
	Files Files
}

func GetTemplateFunctions(tb testing.TB) TemplateFuncs {
	tb.Helper()

	return TemplateFuncs{
		Files: Files{tb: tb},
	}
}

func GetTemplateUtilityFunctions() template.FuncMap {
	return template.FuncMap{
		"base64encode": encodeBase64,
		"base64decode": decodeBase64,
	}
}

type Files struct {
	tb testing.TB
}

func (f Files) Get(relativePathToFile string) (string, error) {
	path := PathToDir(f.tb, relativePathToFile)

	fileBytes, err := ioutil.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("failed to read from source: %w", err)
	}

	return string(fileBytes), nil
}

func encodeBase64(data string) string {
	return base64.StdEncoding.EncodeToString([]byte(data))
}

func decodeBase64(data string) (string, error) {
	decodedBytes, err := base64.StdEncoding.DecodeString(data)
	if err != nil {
		return "", err
	}

	return string(decodedBytes), nil
}
