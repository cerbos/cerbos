// Copyright 2021 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"
	"github.com/cerbos/cerbos/hack/tools/confdocs"
	"log"
	"path/filepath"
	"runtime"
)

const (
	interfacePackage = "github.com/cerbos/cerbos/internal/config"
	interfaceName    = "Section"
)

func main() {
	internalDir, err := getAbsToInternalDir()
	if err != nil {
		log.Fatalf(err.Error())
	}

	dir, err := filepath.Abs(internalDir)
	if err != nil {
		log.Fatalf(err.Error())
	}

	confDoc := confdocs.NewConfDoc(dir, interfaceName, interfacePackage)
	err = confDoc.Run()
	if err != nil {
		log.Fatalf(err.Error())
	}
}

func getAbsToInternalDir() (string, error) {
	_, pathToFile, _, ok := runtime.Caller(0)

	if !ok {
		return "", fmt.Errorf("couldn't find path")
	}

	return filepath.Join(filepath.Dir(pathToFile), "./../../internal"), nil
}
