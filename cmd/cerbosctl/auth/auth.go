// Copyright 2021 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package auth

import (
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"os/user"
	"path/filepath"
)

func getConfigPath() (dir, file string) {
	user, err := user.Current()
	if err != nil {
		panic(err)
	}

	// by default we use XDG_CONFIG_HOME for storing the auth credentials
	// if the value is not set we store file in user home
	if xdgConfigHome := os.Getenv("XDG_CONFIG_HOME"); xdgConfigHome != "" {
		return filepath.Join(xdgConfigHome, "cerbosctl"), "auth"
	}

	return user.HomeDir, ".cerbosctl"
}

func GetToken() (string, error) {
	configDir, fileName := getConfigPath()
	fullPath := filepath.Join(configDir, fileName)

	if _, err := os.Stat(fullPath); err != nil {
		return "", errors.New("could not read credentials file. did you log in?")
	}

	fileContents, err := ioutil.ReadFile(fullPath)
	if err != nil {
		return "", fmt.Errorf("could not read credentials file: %w", err)
	}

	return string(fileContents), nil
}

func SaveToken(token string) error {
	configDir, fileName := getConfigPath()
	fullPath := filepath.Join(configDir, fileName)

	_, err := GetToken()
	if err != nil {
		if err := os.MkdirAll(configDir, 0700); err != nil { //nolint:gomnd
			return err
		}
	}

	if err := ioutil.WriteFile(fullPath, []byte(token), 0600); err != nil { //nolint:gomnd
		return fmt.Errorf("cannot save the credentials: %w", err)
	}

	return nil
}
