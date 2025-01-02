// Copyright 2021-2025 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package errors

import "fmt"

func NewPutError(path, message string) *PutError {
	return &PutError{
		Path:    path,
		Message: message,
	}
}

type PutError struct {
	Path    string
	Message string
}

func (pe *PutError) Error() string {
	return fmt.Sprintf("%s | %s", pe.Path, pe.Message)
}
