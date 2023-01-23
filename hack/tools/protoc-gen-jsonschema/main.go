// Copyright 2021-2023 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"github.com/cerbos/cerbos/hack/tools/protoc-gen-jsonschema/module"
	pgs "github.com/lyft/protoc-gen-star/v2"
)

func main() {
	pgs.Init(pgs.DebugEnv("DEBUG")).RegisterModule(module.New()).Render()
}
