// Copyright 2021 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package test

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"testing"
	"text/template"

	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"

	policyv1 "github.com/cerbos/cerbos/api/genpb/cerbos/policy/v1"
	"github.com/cerbos/cerbos/internal/observability/logging"
	"github.com/cerbos/cerbos/internal/policy"
	"github.com/cerbos/cerbos/internal/schema"
	"github.com/cerbos/cerbos/internal/storage"
	"github.com/cerbos/cerbos/internal/util"
)

func init() {
	if logLevel := os.Getenv("CERBOS_TEST_LOG_LEVEL"); logLevel != "" {
		logging.InitLogging(logLevel)
	}
}

func LoadPolicy(t *testing.T, path string) *policyv1.Policy {
	t.Helper()

	inp := mkReadCloser(t, path)
	defer inp.Close()

	p, err := policy.ReadPolicy(inp)
	require.NoError(t, err, "Failed to load %s", path)

	return p
}

func AddSchemasToStore(t *testing.T, dir string, ms storage.MutableStore) {
	t.Helper()

	fsys := os.DirFS(dir)
	err := fs.WalkDir(fsys, ".", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}

		if d.IsDir() {
			return nil
		}

		if !util.IsSupportedFileType(d.Name()) {
			return nil
		}

		sch := ReadSchemaFromFS(t, fsys, path)

		err = ms.AddOrUpdateSchema(context.TODO(), path, sch)
		require.NoError(t, err)

		return nil
	})
	require.NoError(t, err)
}

func ReadSchemaFromFile(t *testing.T, path string) []byte {
	t.Helper()

	inp := mkReadCloser(t, path)
	defer inp.Close()

	data, err := io.ReadAll(inp)
	require.NoError(t, err, "Failed to load %s", path)

	return data
}

func ReadSchemaFromFS(t *testing.T, fsys fs.FS, path string) []byte {
	t.Helper()

	f, err := fsys.Open(path)
	require.NoError(t, err, "Failed to open %s", path)

	defer f.Close()

	data, err := io.ReadAll(io.Reader(f))
	require.NoError(t, err, "failed to read from source: %w", err)

	return data
}

func mkReadCloser(t *testing.T, file string) io.ReadCloser {
	t.Helper()

	f, err := os.Open(file)
	require.NoError(t, err, "Failed to open file %s", file)

	return f
}

func PathToDir(tb testing.TB, dir string) string {
	tb.Helper()

	_, currFile, _, ok := runtime.Caller(0)
	if !ok {
		tb.Error("Failed to detect testdata directory")
		return ""
	}

	return filepath.Join(filepath.Dir(currFile), "testdata", dir)
}

type Case struct {
	Name  string
	Input []byte
	Want  map[string][]byte
}

// LoadTestCases loads groups of test files from the given path.
// Consider a directory containing the following set of files:
// |- test01.yaml
// |- test01.yaml.err
// |- test01.yaml.out
//
// The above files will be converted to a Case object as follows:
// Case {
//   Name: "test01",
//   Input: <contents_of_test01.yaml>,
//   Want: map[string][]byte{
//     "err": <contents_of_test01.yaml.err>,
//     "out": <contents_of_test01.yaml.out>,
//   }
// }.
func LoadTestCases(tb testing.TB, subDir string) []Case {
	tb.Helper()

	dir := PathToDir(tb, subDir)

	var entries []string
	err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}

		if d.IsDir() {
			return nil
		}

		if filepath.Ext(path) == ".yaml" {
			entries = append(entries, path)
		}

		return nil
	})

	require.NoError(tb, err)

	testCases := make([]Case, len(entries))

	for i, entry := range entries {
		name, err := filepath.Rel(dir, strings.TrimSuffix(entry, filepath.Ext(entry)))
		require.NoError(tb, err)

		testCases[i] = Case{
			Name:  name,
			Input: readFileContents(tb, entry),
		}

		tmpl, err := template.New(entry).Funcs(GetTemplateUtilityFunctions()).Parse(string(testCases[i].Input))
		require.NoError(tb, err)

		var output bytes.Buffer

		err = tmpl.Execute(&output, GetTemplateFunctions(tb))
		require.NoError(tb, err)

		testCases[i].Input = output.Bytes()

		wantedFiles, err := filepath.Glob(fmt.Sprintf("%s.*", entry))
		require.NoError(tb, err)

		testCases[i].Want = make(map[string][]byte, len(wantedFiles))

		for _, wanted := range wantedFiles {
			key := strings.TrimPrefix(filepath.Ext(wanted), ".")
			testCases[i].Want[key] = readFileContents(tb, wanted)
		}
	}

	sort.SliceStable(testCases, func(i, j int) bool {
		return testCases[i].Name < testCases[j].Name
	})

	return testCases
}

func readFileContents(tb testing.TB, filePath string) []byte {
	tb.Helper()

	if _, err := os.Stat(filePath); err == nil {
		b, err := os.ReadFile(filePath)
		if err != nil {
			tb.Errorf("Failed to read %s: %s", filePath, err)
			return nil
		}

		return b
	}

	return nil
}

func ReadSingleTestCase(tb testing.TB, filePath string, out proto.Message) {
	tb.Helper()

	fullPath := PathToDir(tb, filePath)
	data := readFileContents(tb, fullPath)

	tmpl, err := template.New(fullPath).Funcs(GetTemplateUtilityFunctions()).Parse(string(data))
	require.NoError(tb, err)

	buf := new(bytes.Buffer)
	require.NoError(tb, tmpl.Execute(buf, GetTemplateFunctions(tb)))
	require.NoError(tb, util.ReadJSONOrYAML(buf, out))
}

func SkipIfGHActions(t *testing.T) {
	t.Helper()

	if isGH, ok := os.LookupEnv("GITHUB_ACTIONS"); ok && isGH == "true" {
		t.Skipf("Skipping because of known issue with GitHub Actions")
	}
}

func FindPolicyFiles(t *testing.T, dir string, callback func(string) error) error {
	t.Helper()

	testdataDir := PathToDir(t, dir)
	return filepath.WalkDir(testdataDir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}

		if d.IsDir() {
			switch d.Name() {
			case schema.Directory:
				return fs.SkipDir
			case util.TestDataDirectory:
				return fs.SkipDir
			default:
				return nil
			}
		}

		if !util.IsSupportedFileType(d.Name()) {
			return nil
		}

		return callback(path)
	})
}
