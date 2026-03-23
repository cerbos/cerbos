// Copyright 2021-2026 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package crosspath_test

import (
	"strconv"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/cerbos/cerbos/internal/conditions/crosspath"
)

func TestEncodeAndDecode(t *testing.T) {
	testCases := []struct {
		path string
	}{
		{
			path: "/path/to/dir",
		},
		{
			path: "/path/to/file.txt",
		},
		{
			path: `C:\path\to\dir`,
		},
		{
			path: `C:\path\to\file.txt`,
		},
		{
			path: `\\path\to\dir`,
		},
		{
			path: `\\path\to\file.txt`,
		},
	}

	for idx, testCase := range testCases {
		t.Run(strconv.Itoa(idx), func(t *testing.T) {
			path, md := crosspath.Encode(testCase.path)
			require.Equal(t, testCase.path, crosspath.Decode(path, md))
		})
	}
}

func TestAbs(t *testing.T) {
	testCases := []struct {
		path     string
		expected string
	}{
		{path: "/path/to/file.txt", expected: "/path/to/file.txt"},
		{path: `\\host\share\file.txt`, expected: `\\host\share\file.txt`},
		{path: `C:\path\to\file.txt`, expected: `C:\path\to\file.txt`},
	}

	for idx, testCase := range testCases {
		t.Run(strconv.Itoa(idx), func(t *testing.T) {
			have, err := crosspath.Abs(testCase.path)
			require.NoError(t, err)
			require.Equal(t, testCase.expected, have)
		})
	}
}

func TestBase(t *testing.T) {
	testCases := []struct {
		path     string
		expected string
	}{
		{path: ".", expected: "."},
		{path: "..", expected: ".."},
		{path: "/path/to/dir", expected: "dir"},
		{path: `\\host\share\dir`, expected: "dir"},
		{path: `\\host\share\dir\`, expected: "dir"},
		{path: `C:\\path\\to\\dir`, expected: "dir"},
		{path: `C:\\path\\to\\dir\\`, expected: "dir"},
		{path: `C:\\path\\to\\..\\dir`, expected: "dir"},
	}

	for idx, testCase := range testCases {
		t.Run(strconv.Itoa(idx), func(t *testing.T) {
			have := crosspath.Base(testCase.path)
			require.Equal(t, testCase.expected, have)
		})
	}
}

func TestDir(t *testing.T) {
	testCases := []struct {
		path     string
		expected string
	}{
		{path: "/path/to/file.txt", expected: "/path/to"},
		{path: `\\host\share\file.txt`, expected: `\\host\share`},
		{path: "/", expected: "/"},
		{path: `C:\`, expected: `C:\`},
		{path: `\\host\share`, expected: `\\host\share`},
		{path: "./path/to", expected: "path"},
		{path: "../path/to", expected: "../path"},
		{path: `C:\path\to\file.txt`, expected: `C:\path\to`},
		{path: `C:\path\to\dir\`, expected: `C:\path\to`},
		{path: `C:\path\\to\file.txt`, expected: `C:\path\to`},
	}

	for idx, testCase := range testCases {
		t.Run(strconv.Itoa(idx), func(t *testing.T) {
			have := crosspath.Dir(testCase.path)
			require.Equal(t, testCase.expected, have)
		})
	}
}

func TestExt(t *testing.T) {
	testCases := []struct {
		path     string
		expected string
	}{
		{path: "/path/to/file.txt", expected: ".txt"},
		{path: `\\host\share\file.txt`, expected: ".txt"},
		{path: `C:\path\to\file.txt`, expected: ".txt"},
	}

	for idx, testCase := range testCases {
		t.Run(strconv.Itoa(idx), func(t *testing.T) {
			have := crosspath.Ext(testCase.path)
			require.Equal(t, testCase.expected, have)
		})
	}
}

func TestJoin(t *testing.T) {
	testCases := []struct {
		paths    []string
		expected string
	}{
		{
			paths:    paths(""),
			expected: "",
		},
		{
			paths:    paths("C:"),
			expected: "C:",
		},
		{
			paths:    paths("/path", "to", "file.txt"),
			expected: "/path/to/file.txt",
		},
		{
			paths:    paths(`\\host`, "share", "file.txt"),
			expected: `\\host\share\file.txt`,
		},
		{
			paths:    paths(`\\host`, "share"),
			expected: `\\host\share`,
		},
		{
			paths:    paths("C:", "path", "to", "file.txt"),
			expected: `C:\path\to\file.txt`,
		},
	}

	for idx, testCase := range testCases {
		t.Run(strconv.Itoa(idx), func(t *testing.T) {
			have := crosspath.Join(testCase.paths...)
			require.Equal(t, testCase.expected, have)
		})
	}
}

func TestMatch(t *testing.T) {
	testCases := []struct {
		paths    []string
		expected bool
	}{
		{
			paths:    paths("/path/to/file.zip", "/path/to/*.zip"),
			expected: true,
		},
		{
			paths: paths("/path/to/file.zip", "/path/to/*.txt"),
		},
		{
			paths:    paths(`\\host\share\file.zip`, `\\host\share\*.zip`),
			expected: true,
		},
		{
			paths: paths(`\\host\share\file.zip`, `\\host\share\*.txt`),
		},
		{
			paths:    paths(`C:\path\to\file.zip`, `C:\path\to\*.zip`),
			expected: true,
		},
		{
			paths: paths(`C:\path\to\file.zip`, `C:\path\to\*.txt`),
		},
	}

	for idx, testCase := range testCases {
		t.Run(strconv.Itoa(idx), func(t *testing.T) {
			require.Len(t, testCase.paths, 2, "invalid test input")
			have, err := crosspath.Match(testCase.paths[0], testCase.paths[1])
			require.NoError(t, err)
			require.Equal(t, testCase.expected, have)
		})
	}
}

func TestRel(t *testing.T) {
	testCases := []struct {
		paths    []string
		expected string
	}{
		{
			paths:    paths("/path/to", "/path/to"),
			expected: ".",
		},
		{
			paths:    paths("/path/to", "/path/to/file.txt"),
			expected: "file.txt",
		},
		{
			paths:    paths("/path/to/dir", "/path/to/other_dir"),
			expected: "../other_dir",
		},
		{
			paths:    paths(`\\host\share`, `\\host\share`),
			expected: ".",
		},
		{
			paths:    paths(`\\host\share`, `\\host\share\file.txt`),
			expected: "file.txt",
		},
		{
			paths:    paths(`\\host\share\object`, `\\host\share\othere_object`),
			expected: `..\othere_object`,
		},
		{
			paths:    paths(`C:\path\to`, `C:\path\to\file.txt`),
			expected: "file.txt",
		},
		{
			paths:    paths(`C:\path\to`, `C:\path\to`),
			expected: ".",
		},
		{
			paths:    paths(`C:\path\to\dir`, `C:\path\to\othere_dir`),
			expected: `..\othere_dir`,
		},
	}

	for idx, testCase := range testCases {
		t.Run(strconv.Itoa(idx), func(t *testing.T) {
			require.Len(t, testCase.paths, 2, "invalid test input")
			have, err := crosspath.Rel(testCase.paths[0], testCase.paths[1])
			require.NoError(t, err)
			require.Equal(t, testCase.expected, have)
		})
	}
}

func TestVolumeName(t *testing.T) {
	testCases := []struct {
		path     string
		expected string
	}{
		{
			path:     "/path/to/dir",
			expected: "",
		},
		{
			path:     `\\host\share\dir`,
			expected: `\\host\share`,
		},
		{
			path:     `C:\path\to\dir`,
			expected: "C:",
		},
	}

	for idx, testCase := range testCases {
		t.Run(strconv.Itoa(idx), func(t *testing.T) {
			have := crosspath.VolumeName(testCase.path)
			require.Equal(t, testCase.expected, have)
		})
	}
}

func paths(paths ...string) []string {
	return paths
}
