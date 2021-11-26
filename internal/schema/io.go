// Copyright 2021 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package schema

import (
	"bytes"
	"fmt"
	"io"
	"io/ioutil"

	schemav1 "github.com/cerbos/cerbos/api/genpb/cerbos/schema/v1"
	"github.com/cerbos/cerbos/internal/util"
)

func ReadSchemaFromFile(filePath string) (*schemav1.Schema, error) {
	file, err := ioutil.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to open %s: %w", filePath, err)
	}

	return ReadSchema(bytes.NewReader(file))
}

// ReadSchema reads a schema from the given reader.
func ReadSchema(src io.Reader) (*schemav1.Schema, error) {
	sch := &schemav1.Schema{}
	if err := util.ReadJSONOrYAML(src, sch); err != nil {
		return nil, err
	}

	return sch, nil
}
