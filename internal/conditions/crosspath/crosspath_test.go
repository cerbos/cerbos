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
		"path/to/dir",
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
			encoded, err := crosspath.Encode(testCase)
			require.NoError(t, err)
			require.Equal(t, testCase, crosspath.Decode(encoded))
		})
	}
}

func TestBase(t *testing.T) {
	testCases := []struct {
		path string
		want string
	}{
		{path: ".", want: "."},
		{path: "..", want: ".."},
		// UNIX
		{path: "/path/to/dir", want: "dir"},

		// UNC
		{path: `\\host\share\dir`, want: "dir"},
		{path: `\\host\share\dir\`, want: "dir"},

		// Win32
		{path: `C:\\path\\to\\dir`, want: "dir"},
		{path: `C:\\path\\to\\dir\\`, want: "dir"},
		{path: `C:\\path\\to\\..\\dir`, want: "dir"},
	}

	for idx, testCase := range testCases {
		t.Run(strconv.Itoa(idx), func(t *testing.T) {
			have, err := crosspath.Base(testCase.path)
			require.NoError(t, err)
			require.Equal(t, testCase.want, have)
		})
	}
}

func TestDir(t *testing.T) {
	testCases := []struct {
		path      string
		want      string
		expectErr bool
	}{
		// directory
		{path: "/path/to/dir", want: "/path/to"},
		{path: `\\host\share\path\to\dir`, want: `\\host\share\path\to`},
		{path: `\\host\share\dir`, want: `\\host\share`},
		{path: `C:\path\to\dir`, want: `C:\path\to`},

		// file
		{path: "/path/to/file.txt", want: "/path/to"},
		{path: `\\host\share\path\to\file.txt`, want: `\\host\share\path\to`},
		{path: `\\host\share\file.txt`, want: `\\host\share`},
		{path: `C:\path\to\file.txt`, want: `C:\path\to`},

		// root
		{path: "/", want: "/"},
		{path: `\\host\share`, want: `\\host\share`},
		{path: `C:\`, want: `C:\`},
		{path: `C:`, want: `C:\`},
		{path: `C:.`, expectErr: true},
		{path: `C:dir`, expectErr: true},

		// relative
		{path: "./path/to/dir", want: "path/to"},
		{path: `path\to\dir`, want: `path\to`},

		// up
		{path: "../path/to/dir", want: "../path/to"},
		{path: `..\path\to\dir`, want: `..\path\to`},

		// leading
		{path: "/path/to/dir/", want: "/path/to"},
		{path: `\\host\share\path\to\dir\`, want: `\\host\share\path\to`},
		{path: `\\host\share\dir\`, want: `\\host\share`},
		{path: `C:\path\to\dir\`, want: `C:\path\to`},

		// double slash
		{path: "/path//to/file.txt", want: "/path/to"},
		{path: `\\host\share\path\\to\file.txt`, want: `\\host\share\path\to`},
		{path: `\\host\share\\file.txt`, want: `\\host\share`},
		{path: `C:\path\\to\file.txt`, want: `C:\path\to`},
	}

	for idx, testCase := range testCases {
		t.Run(strconv.Itoa(idx), func(t *testing.T) {
			have, err := crosspath.Dir(testCase.path)
			if testCase.expectErr {
				require.Error(t, err)
			} else {
				require.Equal(t, testCase.want, have)
			}
		})
	}
}

func TestExt(t *testing.T) {
	testCases := []struct {
		path string
		want string
	}{
		{path: "/path/to/file.txt", want: ".txt"},
		{path: `\\host\share\file.txt`, want: ".txt"},
		{path: `C:\path\to\file.txt`, want: ".txt"},
	}

	for idx, testCase := range testCases {
		t.Run(strconv.Itoa(idx), func(t *testing.T) {
			have, err := crosspath.Ext(testCase.path)
			require.NoError(t, err)
			require.Equal(t, testCase.want, have)
		})
	}
}

func TestJoin(t *testing.T) {
	testCases := []struct {
		paths []string
		want  string
	}{
		{
			paths: nil,
			want:  "",
		},
		{
			paths: paths(""),
			want:  "",
		},

		// UNIX
		{
			paths: paths("/path", "to", "dir"),
			want:  "/path/to/dir",
		},
		{
			paths: paths("/path", "to", "dir", ".."),
			want:  "/path/to",
		},
		{
			paths: paths("path", "to", "dir"),
			want:  "path/to/dir",
		},
		{
			paths: paths("path", "to", "dir", ".."),
			want:  "path/to",
		},
		{
			paths: paths("/path", "to", "file.txt"),
			want:  "/path/to/file.txt",
		},
		{
			paths: paths("/"),
			want:  "/",
		},

		// UNC
		{
			paths: paths(`\\host`, "share", "path", "to", "dir"),
			want:  `\\host\share\path\to\dir`,
		},
		{
			paths: paths(`\\host`, "share", "path", "to", "dir", ".."),
			want:  `\\host\share\path\to`,
		},
		{
			paths: paths(`\\host`, "share", "file.txt"),
			want:  `\\host\share\file.txt`,
		},
		{
			paths: paths(`\\host`, "share"),
			want:  `\\host\share`,
		},

		// Win32
		{
			paths: paths("C:", "path", "to", "dir"),
			want:  `C:\path\to\dir`,
		},
		{
			paths: paths("C:", "path", "to", "dir", ".."),
			want:  `C:\path\to`,
		},
		{
			paths: paths(`\path`, "to", "dir"),
			want:  `\path\to\dir`,
		},
		{
			paths: paths(`\path`, "to", "dir", ".."),
			want:  `\path\to`,
		},
		{
			paths: paths("C:", "path", "to", "file.txt"),
			want:  `C:\path\to\file.txt`,
		},
		{
			paths: paths(`C:\`),
			want:  `C:\`,
		},
	}

	for idx, testCase := range testCases {
		t.Run(strconv.Itoa(idx), func(t *testing.T) {
			have, err := crosspath.Join(testCase.paths...)
			require.NoError(t, err)
			require.Equal(t, testCase.want, have)
		})
	}
}

func TestMatch(t *testing.T) {
	testCases := []struct {
		paths []string
		want  bool
	}{
		// UNIX
		{
			paths: paths("/path/to/file.zip", "/path/to/*.zip"),
			want:  true,
		},
		{
			paths: paths("/path/to/../file.zip", "/path/to/../*.zip"),
			want:  true,
		},
		{
			paths: paths("/path/to/file.zip", "/path/to/*.txt"),
		},

		// UNC
		{
			paths: paths(`\\host\share\file.zip`, `\\host\share\*.zip`),
			want:  true,
		},
		{
			paths: paths(`\\host\share\..\file.zip`, `\\host\share\..\*.zip`),
			want:  true,
		},
		{
			paths: paths(`\\host\share\file.zip`, `\\host\share\*.txt`),
		},

		// Win32
		{
			paths: paths(`C:\path\to\file.zip`, `C:\path\to\*.zip`),
			want:  true,
		},
		{
			paths: paths(`C:\path\to\..\file.zip`, `C:\path\to\..\*.zip`),
			want:  true,
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
			require.Equal(t, testCase.want, have)
		})
	}
}

func TestRel(t *testing.T) {
	testCases := []struct {
		paths []string
		want  string
	}{
		// UNIX
		{
			paths: paths("/path/to/dir", "/path/to/dir"),
			want:  ".",
		},
		{
			paths: paths("/path/to/dir", "/path/to"),
			want:  "..",
		},
		{
			paths: paths("/path/to", "/path/to/file.txt"),
			want:  "file.txt",
		},
		{
			paths: paths("/path/to/dir", "/path/to/other_dir"),
			want:  "../other_dir",
		},
		{
			paths: paths("/path/to/../dir", "/path/to/../other_dir"),
			want:  "../other_dir",
		},
		{
			paths: paths("path/to/dir", "path/to/other_dir"),
			want:  "../other_dir",
		},

		// UNC
		{
			paths: paths(`\\host\share\path\to\dir`, `\\host\share\path\to\dir`),
			want:  ".",
		},
		{
			paths: paths(`\\host\share\path\to\dir`, `\\host\share\path\to`),
			want:  "..",
		},
		{
			paths: paths(`\\host\share`, `\\host\share\file.txt`),
			want:  "file.txt",
		},
		{
			paths: paths(`\\host\share\object`, `\\host\share\other_object`), //nolint:misspell
			want:  `..\other_object`,                                         //nolint:misspell
		},
		{
			paths: paths(`\\host\share\path\to\..\dir\object`, `\\host\share\path\to\..\dir\other_object`), //nolint:misspell
			want:  `..\other_object`,                                                                       //nolint:misspell
		},

		// Win32
		{
			paths: paths(`C:\path\to\dir`, `C:\path\to\dir`),
			want:  ".",
		},
		{
			paths: paths(`C:\path\to\dir`, `C:\path\to`),
			want:  "..",
		},
		{
			paths: paths(`C:\path\to`, `C:\path\to\file.txt`),
			want:  "file.txt",
		},
		{
			paths: paths(`C:\path\to\dir`, `C:\path\to\other_dir`), //nolint:misspell
			want:  `..\other_dir`,                                  //nolint:misspell
		},
		{
			paths: paths(`C:\path\to\..\dir`, `C:\path\to\..\other_dir`), //nolint:misspell
			want:  `..\other_dir`,                                        //nolint:misspell
		},
		{
			paths: paths(`path\to\dir`, `path\to\other_dir`), //nolint:misspell
			want:  `..\other_dir`,                            //nolint:misspell
		},
	}

	for idx, testCase := range testCases {
		t.Run(strconv.Itoa(idx), func(t *testing.T) {
			require.Len(t, testCase.paths, 2, "invalid test input")
			have, err := crosspath.Rel(testCase.paths[0], testCase.paths[1])
			require.NoError(t, err)
			require.Equal(t, testCase.want, have)
		})
	}
}

func TestVolumeName(t *testing.T) {
	testCases := []struct {
		path string
		want string
	}{
		// UNIX
		{
			path: "/path/to/dir",
			want: "",
		},
		{
			path: "/",
			want: "",
		},

		// UNC
		{
			path: `\\host\share\dir`,
			want: `\\host\share`,
		},
		{
			path: `\\host\share`,
			want: `\\host\share`,
		},

		// Win32
		{
			path: `C:\path\to\dir`,
			want: "C:",
		},
		{
			path: `C:\`,
			want: "C:",
		},
		{
			path: `C:`,
			want: "C:",
		},
	}

	for idx, testCase := range testCases {
		t.Run(strconv.Itoa(idx), func(t *testing.T) {
			have := crosspath.VolumeName(testCase.path)
			require.Equal(t, testCase.want, have)
		})
	}
}

func paths(paths ...string) []string {
	return paths
}
