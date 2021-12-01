// Copyright 2021 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"github.com/cerbos/cerbos/hack/tools/confdocs"
	"log"
	"os"
	"path/filepath"
)

const (
	interfacePackage = "github.com/cerbos/cerbos/internal/config"
	interfaceName    = "Section"
)

func main() {
	cwd, err := os.Getwd()
	if err != nil {
		log.Fatalf(err.Error())
	}

	dir, err := filepath.Abs(cwd)
	if err != nil {
		log.Fatalf(err.Error())
	}

	confDoc := confdocs.NewConfDoc(dir, interfaceName, interfacePackage)
	err = confDoc.Run()
	if err != nil {
		log.Fatalf(err.Error())
	}
}

