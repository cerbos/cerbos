// Copyright 2021-2026 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package crosspath

import (
	"fmt"
	"path/filepath"
	"strings"
)

const noOfPartsInUNCPaths = 3

// Encoded is an encoded path.
//
// UNIX paths are encoded as-is,
// UNC absolute paths such as `\\host\share\path\to\dir` encoded as `/host/share/path/to/dir`.
// Win32 absolute paths such as `C:\path\to\dir` encoded as `/C:/path/to/dir`,
// Win32 relative paths such as `path\to\dir` encoded as `path/to/dir`.
type Encoded struct {
	value string
	kind  Kind
	win32 bool
	root  bool
}

// Encode encodes a UNIX or Win32 path as Encoded.
func Encode(path string) Encoded {
	var encoded Encoded

	if strings.Contains(path, `\`) {
		encoded.win32 = true
	}

	switch {
	case isUNCPath(path):
		encoded.kind = KindUNC
		encoded.value = toSlash(path)

		// The path has a value such as `\\host\share` which means it is root.
		if subs := strings.SplitN(path[2:], `\`, noOfPartsInUNCPaths); len(subs) == 2 { //nolint:mnd
			encoded.root = true
		}
	case isDrivePath(path):
		encoded.kind = KindDrive
		encoded.value = toSlash(`\` + path)

		// The path has a value such as `D:` or `D:/` which means it is root.
		if len(path) == 2 || len(path) == 3 {
			encoded.root = true
		}
	default:
		encoded.kind = KindUnknown
		if encoded.win32 {
			encoded.value = toSlash(path)
		} else {
			encoded.value = path
			if encoded.value == "/" {
				encoded.root = true
			}
		}
	}

	encoded.value = filepath.Clean(encoded.value)
	return encoded
}

// Decode decodes an Encoded path in its original encoding.
func Decode(encoded Encoded) string {
	switch {
	case encoded.kind == KindUNC:
		// Add the leading `\` we have removed while encoding the path (`\host\share\dir` -> `\\host\share\dir`).
		return `\` + toBackslash(encoded.value)
	case encoded.kind == KindDrive:
		// Trim the leading `/` we have added while encoding the path (`\c:\path\to\dir` -> `c:\path\to\dir`).
		return strings.TrimPrefix(toBackslash(encoded.value), `\`)
	case encoded.kind == KindUnknown && encoded.win32:
		return toBackslash(encoded.value)
	default:
		return encoded.value
	}
}

// Abs returns an absolute representation of path against the work directory.
func Abs(workDir, path string) (string, error) {
	if strings.HasPrefix(path, workDir) {
		encodedPath := Encode(path)
		return Decode(encodedPath), nil
	}

	return Join(workDir, path), nil
}

// Base returns the last element of path.
func Base(path string) string {
	return filepath.Base(Encode(path).value)
}

// Dir returns all but the last element of path, typically the path's directory.
func Dir(path string) string {
	encoded := Encode(path)
	switch {
	case encoded.kind == KindUNC:
		if encoded.root {
			return Decode(encoded)
		}

		idx := strings.LastIndex(encoded.value, "/")
		encoded.value = encoded.value[:idx]
		return Decode(encoded)
	case encoded.kind == KindDrive:
		if encoded.root {
			return Decode(encoded) + `\`
		}

		idx := strings.LastIndex(encoded.value, "/")
		encoded.value = encoded.value[:idx]
		return Decode(encoded)
	case encoded.kind == KindUnknown && encoded.win32:
		idx := strings.LastIndex(encoded.value, "/")
		encoded.value = encoded.value[:idx]
		return Decode(encoded)
	default:
		encoded.value = filepath.Dir(encoded.value)
		return Decode(encoded)
	}
}

// Ext returns the file name extension used by path.
func Ext(path string) string {
	return filepath.Ext(Encode(path).value)
}

// Join joins any number of path elements into a single path.
func Join(paths ...string) string {
	switch len(paths) {
	case 0:
		return ""
	case 1:
		return paths[0]
	default:
		result := Encode(paths[0])
		for i := 1; i < len(paths); i++ {
			encoded := Encode(paths[i])
			result.value = filepath.Join(result.value, encoded.value)
		}

		return Decode(result)
	}
}

func Match(path, pattern string) (bool, error) {
	encoded := Encode(path)
	encodedPattern := Encode(pattern)
	matched, err := filepath.Match(encodedPattern.value, encoded.value)
	if err != nil {
		return false, fmt.Errorf("failed to match pattern %q on path %q: %w", pattern, path, err)
	}

	return matched, nil
}

// Rel returns a relative path that is lexically equivalent to targetPath when
// joined to basePath with an intervening separator. That is,
// [Join](basePath, Rel(basePath, targPath)) is equivalent to targPath itself.
func Rel(basePath, targetPath string) (string, error) {
	encodedBasePath := Encode(basePath)
	encodedTargetPath := Encode(targetPath)

	var err error
	if encodedTargetPath.value, err = filepath.Rel(encodedBasePath.value, encodedTargetPath.value); err != nil {
		return "", fmt.Errorf("failed to determine relative path of %s: %w", targetPath, err)
	}

	if encodedTargetPath.value == "." || encodedTargetPath.value == ".." {
		return encodedTargetPath.value, nil
	}

	if encodedTargetPath.kind == KindUNC && !strings.HasPrefix(encodedTargetPath.value, `\`) {
		return toBackslash(encodedTargetPath.value), nil
	}

	return Decode(encodedTargetPath), nil
}

// VolumeName returns leading volume name for Windows paths.
// Given a Windows path
//   - "C:\foo\bar" it returns "C:".
//   - "\\host\share\foo" it returns "\\host\share".
//
// Otherwise, it returns empty string.
func VolumeName(path string) string {
	switch {
	case isUNCPath(path):
		subs := strings.SplitN(path[2:], `\`, noOfPartsInUNCPaths)
		if len(subs) > 1 && subs[0] != "" && subs[1] != "" {
			return `\\` + subs[0] + `\` + subs[1]
		}
	case isDrivePath(path):
		return path[:2]
	}

	return ""
}

type Kind uint32

const (
	KindUnknown Kind = iota
	KindDrive
	KindUNC
)

func isUNCPath(path string) bool {
	return strings.HasPrefix(path, `\\`)
}

func isDrivePath(path string) bool {
	return len(path) > 1 && path[1] == ':' && validDriveLetter(path[0])
}

func validDriveLetter(letter uint8) bool {
	if letter >= 'a' && letter <= 'z' {
		return true
	} else if letter >= 'A' && letter <= 'Z' {
		return true
	}

	return false
}

func toSlash(path string) string {
	return strings.ReplaceAll(path, `\`, "/")
}

func toBackslash(path string) string {
	return strings.ReplaceAll(path, "/", `\`)
}
