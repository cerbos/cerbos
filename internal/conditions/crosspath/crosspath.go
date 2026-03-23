// Copyright 2021-2026 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package crosspath

import (
	"fmt"
	"path/filepath"
	"strings"
)

const noOfPartsInUNCPaths = 3

type Metadata struct {
	prefix string
	unc    bool
}

// Encode encodes a UNIX or Win32 path as crosspath.
func Encode(path string) (string, *Metadata) {
	md := &Metadata{}
	switch {
	case isUNCPath(path):
		md.unc = true
		subs := strings.SplitN(path[2:], `\`, noOfPartsInUNCPaths)
		if len(subs) > 1 && subs[0] != "" && subs[1] != "" {
			md.prefix = `\\` + subs[0] + `\` + subs[1]
		}
		path = strings.TrimPrefix(path, toSlash(md.prefix))
	case isWinPath(path):
		md.prefix = path[:2]
		path = `\` + md.prefix + path[2:]
	}

	return filepath.Clean(toSlash(path)), md
}

// Decode decodes a crosspath to its original encoding.
func Decode(path string, md *Metadata) string {
	switch {
	case md.unc:
		path = strings.ReplaceAll(path, "/", `\`)
		if strings.HasPrefix(path, `\`) {
			path = `\` + path
		}

		return path
	case md.prefix != "":
		return strings.ReplaceAll(strings.TrimPrefix(path, "/"), "/", `\`)
	default:
		return path
	}
}

// Abs returns an absolute representation of path.
func Abs(path string) (string, error) {
	path, md := Encode(path)
	var err error
	if path, err = filepath.Abs(path); err != nil {
		return "", fmt.Errorf("failed to find absolute path of %q: %w", path, err)
	}

	return Decode(path, md), nil
}

// Base returns the last element of path.
func Base(path string) string {
	path, _ = Encode(path)
	return filepath.Base(path)
}

// Dir returns all but the last element of path, typically the path's directory.
func Dir(path string) string {
	unixPath, md := Encode(path)
	switch {
	case path == md.prefix:
		return md.prefix
	case !md.unc && md.prefix != "" && path == md.prefix+`\`:
		return path
	default:
		dir := filepath.Dir(unixPath)
		decoded := Decode(dir, md)
		return decoded
	}
}

// Ext returns the file name extension used by path.
func Ext(path string) string {
	path, _ = Encode(path)
	return filepath.Ext(path)
}

// Join joins any number of path elements into a single path.
func Join(paths ...string) string {
	switch len(paths) {
	case 0:
		return ""
	case 1:
		return paths[0]
	default:
		result, md := Encode(paths[0])
		for i := 1; i < len(paths); i++ {
			path, _ := Encode(paths[i])
			result = filepath.Join(result, path)
		}

		return Decode(result, md)
	}
}

func Match(path, pattern string) (bool, error) {
	path, _ = Encode(path)
	pattern, _ = Encode(pattern)
	matched, err := filepath.Match(pattern, path)
	if err != nil {
		return false, fmt.Errorf("failed to match pattern %q on path %q: %w", pattern, path, err)
	}

	return matched, nil
}

// Rel returns a relative path that is lexically equivalent to targetPath when
// joined to basePath with an intervening separator. That is,
// [Join](basePath, Rel(basePath, targPath)) is equivalent to targPath itself.
func Rel(basePath, targetPath string) (string, error) {
	basePath, _ = Encode(basePath)
	targetPath, md := Encode(targetPath)

	relPath, err := filepath.Rel(basePath, targetPath)
	if err != nil {
		return "", fmt.Errorf("failed to determine relative path of %s: %w", targetPath, err)
	}

	return Decode(relPath, md), nil
}

// VolumeName returns leading volume name for Windows paths.
// Given a Windows path
//   - "C:\foo\bar" it returns "C:".
//   - "\\host\share\foo" it returns "\\host\share".
//
// Otherwise, it returns empty string.
func VolumeName(path string) string {
	_, md := Encode(path)
	return md.prefix
}

func isUNCPath(path string) bool {
	return strings.HasPrefix(path, `\\`)
}

func isWinPath(path string) bool {
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

func toSlash(p string) string {
	return strings.ReplaceAll(p, `\`, "/")
}
