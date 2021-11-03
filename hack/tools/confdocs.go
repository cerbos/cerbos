// Copyright 2021 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"github.com/cerbos/cerbos/hack/tools/confdocs"
	"log"
	"os"
	"path/filepath"
	"strings"
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
	relative := "."

	cwd, err := os.Getwd()
	if err != nil {
		return "", err
	}

	dir := filepath.Join(cwd, relative)
	if err != nil {
		return "", err
	}

	for !strings.HasSuffix(dir, "cerbos") {
		relative += "/.."

		dir = filepath.Join(cwd, relative)
		if err != nil {
			return "", err
		}
	}

	dir = filepath.Join(dir, "internal")

	absPath, err := filepath.Abs(dir)
	if err != nil {
		return "", err
	}

	return absPath, nil
}
