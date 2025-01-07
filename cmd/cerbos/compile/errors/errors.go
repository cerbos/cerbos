// Copyright 2021-2025 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package errors

import "errors"

var (
	// ErrFailed is the error returned when compilation fails.
	ErrFailed = errors.New("failed to compile")
	// ErrTestsFailed is the error returned when tests fail.
	ErrTestsFailed = errors.New("tests failed")
)
