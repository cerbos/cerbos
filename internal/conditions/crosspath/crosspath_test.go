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
	testCases := []string{
		// UNIX
		"/",
		"/path/to/dir",
		"/path/to/file.txt",

		// UNC
		`\\host\share`,
		`\\host\share\path\to\dir`,
		`\\host\share\dir`,
		`\\host\share\file.txt`,

		// Win32
		`C:`,
		`C:\path\to\dir`,
		`C:\path\to\file.txt`,
		`path\to\dir`,
		`\path\to\dir`,
		`..\path\to\dir`,
		`path\to\file.txt`,
	}

	for idx, testCase := range testCases {
		t.Run(strconv.Itoa(idx), func(t *testing.T) {
			encoded := crosspath.Encode(testCase)
			require.Equal(t, testCase, crosspath.Decode(encoded))
		})
	}
}

func TestAbs(t *testing.T) {
	testCases := []struct {
		workDir  string
		path     string
		expected string
	}{
		// UNIX (workdir=/)
		{
			workDir:  "/",
			path:     "path/to/dir",
			expected: "/path/to/dir",
		},
		{
			workDir:  "/",
			path:     "path/to/file.txt",
			expected: "/path/to/file.txt",
		},
		{
			workDir:  "/",
			path:     "path/to/../../file.txt",
			expected: "/file.txt",
		},
		{
			workDir:  "/",
			path:     "/path/to/dir",
			expected: "/path/to/dir",
		},

		// UNIX (workdir=/workdir)
		{
			workDir:  "/workdir",
			path:     "path/to/dir",
			expected: "/workdir/path/to/dir",
		},
		{
			workDir:  "/workdir",
			path:     "path/to/file.txt",
			expected: "/workdir/path/to/file.txt",
		},
		{
			workDir:  "/workdir",
			path:     "path/to/../../file.txt",
			expected: "/workdir/file.txt",
		},
		{
			workDir:  "/workdir",
			path:     "/workdir/path/to/dir",
			expected: "/workdir/path/to/dir",
		},

		// UNC (workdir=\\host\share)
		{
			workDir:  `\\host\share`,
			path:     `path\to\dir`,
			expected: `\\host\share\path\to\dir`,
		},
		{
			workDir:  `\\host\share`,
			path:     `file.txt`,
			expected: `\\host\share\file.txt`,
		},
		{
			workDir:  `\\host\share`,
			path:     `path\to\..\..\file.txt`,
			expected: `\\host\share\file.txt`,
		},
		{
			workDir:  `\\host\share`,
			path:     `\\host\share\path\to\dir`,
			expected: `\\host\share\path\to\dir`,
		},

		// UNC (workdir=\\host\share\workdir)
		{
			workDir:  `\\host\share\workdir`,
			path:     `path\to\dir`,
			expected: `\\host\share\workdir\path\to\dir`,
		},
		{
			workDir:  `\\host\share\workdir`,
			path:     `file.txt`,
			expected: `\\host\share\workdir\file.txt`,
		},
		{
			workDir:  `\\host\share\workdir`,
			path:     `path\to\..\..\file.txt`,
			expected: `\\host\share\workdir\file.txt`,
		},
		{
			workDir:  `\\host\share\workdir`,
			path:     `\\host\share\workdir\path\to\dir`,
			expected: `\\host\share\workdir\path\to\dir`,
		},

		// Win32 (workdir=C:\)
		{
			workDir:  `C:\`,
			path:     `path\to\dir`,
			expected: `C:\path\to\dir`,
		},
		{
			workDir:  `C:\`,
			path:     `path\to\file.txt`,
			expected: `C:\path\to\file.txt`,
		},
		{
			workDir:  `C:\`,
			path:     `path\to\..\..\file.txt`,
			expected: `C:\file.txt`,
		},
		{
			workDir:  `C:\`,
			path:     `C:\path\to\dir`,
			expected: `C:\path\to\dir`,
		},

		// Win32 (workdir=C:\workdir)
		{
			workDir:  `C:\workdir`,
			path:     `path\to\dir`,
			expected: `C:\workdir\path\to\dir`,
		},
		{
			workDir:  `C:\workdir`,
			path:     `path\to\file.txt`,
			expected: `C:\workdir\path\to\file.txt`,
		},
		{
			workDir:  `C:\workdir`,
			path:     `path\to\..\..\file.txt`,
			expected: `C:\workdir\file.txt`,
		},
		{
			workDir:  `C:\workdir`,
			path:     `C:\workdir\path\to\dir`,
			expected: `C:\workdir\path\to\dir`,
		},
	}

	for idx, testCase := range testCases {
		t.Run(strconv.Itoa(idx), func(t *testing.T) {
			have, err := crosspath.Abs(testCase.workDir, testCase.path)
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
		// UNIX
		{path: "/path/to/dir", expected: "dir"},

		// UNC
		{path: `\\host\share\dir`, expected: "dir"},
		{path: `\\host\share\dir\`, expected: "dir"},

		// Win32
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
		// directory
		{path: "/path/to/dir", expected: "/path/to"},
		{path: `\\host\share\path\to\dir`, expected: `\\host\share\path\to`},
		{path: `\\host\share\dir`, expected: `\\host\share`},
		{path: `C:\path\to\dir`, expected: `C:\path\to`},

		// file
		{path: "/path/to/file.txt", expected: "/path/to"},
		{path: `\\host\share\path\to\file.txt`, expected: `\\host\share\path\to`},
		{path: `\\host\share\file.txt`, expected: `\\host\share`},
		{path: `C:\path\to\file.txt`, expected: `C:\path\to`},

		// root
		{path: "/", expected: "/"},
		{path: `\\host\share`, expected: `\\host\share`},
		{path: `C:\`, expected: `C:\`},
		{path: `C:`, expected: `C:\`}, // TODO(oguzhan): I think this would return `C:.` or perhaps `C:` in Win32

		// relative
		{path: "./path/to/dir", expected: "path/to"},
		{path: `path\to\dir`, expected: `path\to`},

		// up
		{path: "../path/to/dir", expected: "../path/to"},
		{path: `..\path\to\dir`, expected: `..\path\to`},

		// leading
		{path: "/path/to/dir/", expected: "/path/to"},
		{path: `\\host\share\path\to\dir\`, expected: `\\host\share\path\to`},
		{path: `\\host\share\dir\`, expected: `\\host\share`},
		{path: `C:\path\to\dir\`, expected: `C:\path\to`},

		// double slash
		{path: "/path//to/file.txt", expected: "/path/to"},
		{path: `\\host\share\path\\to\file.txt`, expected: `\\host\share\path\to`},
		{path: `\\host\share\\file.txt`, expected: `\\host\share`},
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

		// UNIX
		{
			paths:    paths("/path", "to", "file.txt"),
			expected: "/path/to/file.txt",
		},
		{
			paths:    paths("/"),
			expected: "/",
		},

		// UNC
		{
			paths:    paths(`\\host`, "share", "file.txt"),
			expected: `\\host\share\file.txt`,
		},
		{
			paths:    paths(`\\host`, "share"),
			expected: `\\host\share`,
		},

		// Win32
		{
			paths:    paths("C:", "path", "to", "file.txt"),
			expected: `C:\path\to\file.txt`,
		},
		{
			paths:    paths("C:"),
			expected: "C:",
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
		// UNIX
		{
			paths:    paths("/path/to/file.zip", "/path/to/*.zip"),
			expected: true,
		},
		{
			paths: paths("/path/to/file.zip", "/path/to/*.txt"),
		},

		// UNC
		{
			paths:    paths(`\\host\share\file.zip`, `\\host\share\*.zip`),
			expected: true,
		},
		{
			paths: paths(`\\host\share\file.zip`, `\\host\share\*.txt`),
		},

		// Win32
		{
			paths:    paths(`C:\path\to\file.zip`, `C:\path\to\*.zip`),
			expected: true,
		},
		{
			paths: paths(`C:\path\to\file.zip`, `C:\path\to\*.txt`),
		},
		{
			paths: paths(`D:\path\to\file.zip`, `C:\path\to\*.zip`),
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
		// UNIX
		{
			paths:    paths("/path/to/dir", "/path/to/dir"),
			expected: ".",
		},
		{
			paths:    paths("/path/to/dir", "/path/to"),
			expected: "..",
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
			paths:    paths("/path/to/../dir", "/path/to/../other_dir"),
			expected: "../other_dir",
		},
		{
			paths:    paths("path/to/dir", "path/to/other_dir"),
			expected: "../other_dir",
		},

		// UNC
		{
			paths:    paths(`\\host\share\path\to\dir`, `\\host\share\path\to\dir`),
			expected: ".",
		},
		{
			paths:    paths(`\\host\share\path\to\dir`, `\\host\share\path\to`),
			expected: "..",
		},
		{
			paths:    paths(`\\host\share`, `\\host\share\file.txt`),
			expected: "file.txt",
		},
		{
			paths:    paths(`\\host\share\object`, `\\host\share\other_object`), //nolint:misspell
			expected: `..\other_object`,                                         //nolint:misspell
		},
		{
			paths:    paths(`\\host\share\path\to\..\dir\object`, `\\host\share\path\to\..\dir\other_object`), //nolint:misspell
			expected: `..\other_object`,                                                                       //nolint:misspell
		},

		// Win32
		{
			paths:    paths(`C:\path\to\dir`, `C:\path\to\dir`),
			expected: ".",
		},
		{
			paths:    paths(`C:\path\to\dir`, `C:\path\to`),
			expected: "..",
		},
		{
			paths:    paths(`C:\path\to`, `C:\path\to\file.txt`),
			expected: "file.txt",
		},
		{
			paths:    paths(`C:\path\to\dir`, `C:\path\to\other_dir`), //nolint:misspell
			expected: `..\other_dir`,                                  //nolint:misspell
		},
		{
			paths:    paths(`C:\path\to\..\dir`, `C:\path\to\..\other_dir`), //nolint:misspell
			expected: `..\other_dir`,                                        //nolint:misspell
		},
		{
			paths:    paths(`path\to\dir`, `path\to\other_dir`), //nolint:misspell
			expected: `..\other_dir`,                            //nolint:misspell
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
		// UNIX
		{
			path:     "/path/to/dir",
			expected: "",
		},
		{
			path:     "/",
			expected: "",
		},

		// UNC
		{
			path:     `\\host\share\dir`,
			expected: `\\host\share`,
		},
		{
			path:     `\\host\share`,
			expected: `\\host\share`,
		},

		// Win32
		{
			path:     `C:\path\to\dir`,
			expected: "C:",
		},
		{
			path:     `C:\`,
			expected: "C:",
		},
		{
			path:     `C:`,
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
