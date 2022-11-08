// Copyright 2021-2022 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package files

import "archive/zip"

type Found interface {
	Path() string
}

type FoundFile interface {
	Found
	AbsolutePath() string
}

type FoundZip interface {
	Found
	File() *zip.ReadCloser
}

type foundFileImpl struct {
	absolutePath string
	relativePath string
}

func (f foundFileImpl) AbsolutePath() string {
	return f.absolutePath
}

func (f foundFileImpl) Path() string {
	return f.relativePath
}

type foundZipImpl struct {
	zipFile      *zip.ReadCloser
	relativePath string
}

func (f foundZipImpl) Path() string {
	return f.relativePath
}

func (f foundZipImpl) File() *zip.ReadCloser {
	return f.zipFile
}
