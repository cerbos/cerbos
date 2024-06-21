// Copyright 2021-2024 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"

	policyv1 "github.com/cerbos/cerbos/api/genpb/cerbos/policy/v1"
	requestv1 "github.com/cerbos/cerbos/api/genpb/cerbos/request/v1"
	schemav1 "github.com/cerbos/cerbos/api/genpb/cerbos/schema/v1"
	"github.com/cerbos/cerbos/internal/namer"
	"github.com/cerbos/cerbos/internal/observability/logging"
	"github.com/cerbos/cerbos/internal/policy"
	"github.com/cerbos/cerbos/internal/storage"
	"github.com/cerbos/cerbos/internal/util"
)

func init() {
	if logLevel := os.Getenv("CERBOS_TEST_LOG_LEVEL"); logLevel != "" {
		logging.InitLogging(context.Background(), logLevel)
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

		if err := ms.AddOrUpdateSchema(context.TODO(), requestv1.AddMode_ADD_MODE_REPLACE_IF_EXISTS, &schemav1.Schema{
			Id:         path,
			Definition: ReadSchemaFromFS(t, fsys, path),
		}); err != nil && !errors.Is(err, &storage.InvalidSchemaError{}) {
			var ise storage.InvalidSchemaError
			if ok := errors.As(err, &ise); !ok {
				return err
			}
		}

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

func DataFS() fs.FS {
	_, currFile, _, ok := runtime.Caller(0)
	if !ok {
		panic(fmt.Errorf("failed to determine current dir"))
	}

	return os.DirFS(filepath.Join(filepath.Dir(currFile), "testdata"))
}

type Case struct {
	Want       map[string][]byte
	Name       string
	SourceFile string
	Input      []byte
}

// LoadTestCases loads groups of test files from the given path.
// Consider a directory containing the following set of files:
// |- test01.yaml
// |- test01.yaml.err
// |- test01.yaml.out
//
// The above files will be converted to a Case object as follows:
//
//	Case {
//	  Name: "test01",
//	  Input: <contents_of_test01.yaml>,
//	  Want: map[string][]byte{
//	    "err": <contents_of_test01.yaml.err>,
//	    "out": <contents_of_test01.yaml.out>,
//	  }
//	}.
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

		ext := filepath.Ext(path)
		if ext == ".yaml" || ext == ".json" {
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
			Name:       name,
			Input:      RenderTemplate(tb, entry, nil),
			SourceFile: entry,
		}

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

func SkipIfGHActions(t *testing.T) {
	t.Helper()

	if isGH, ok := os.LookupEnv("GITHUB_ACTIONS"); ok && isGH == "true" {
		t.Skipf("Skipping because of known issue with GitHub Actions")
	}
}

func FindPolicyFiles(t *testing.T, dir string, callback func(string) error) error {
	t.Helper()

	base := PathToDir(t, dir)

	return fs.WalkDir(os.DirFS(base), ".", func(path string, _ fs.DirEntry, err error) error {
		if err != nil {
			return err
		}

		if util.FileType(path) != util.FileTypePolicy {
			return nil
		}

		return callback(filepath.Join(base, path))
	})
}

func FilterPolicies[P *policyv1.Policy | policy.Wrapper](t *testing.T, policies []P, params storage.ListPolicyIDsParams) []P {
	t.Helper()

	filtered := []P{}

	var ss util.StringSet
	if len(params.IDs) > 0 {
		ss = util.ToStringSet(params.IDs)
	}

	c := util.NewRegexpCache()
	for _, p := range policies {
		var wrapped policy.Wrapper
		switch a := any(p).(type) {
		case *policyv1.Policy:
			wrapped = policy.Wrap(a)
		case policy.Wrapper:
			wrapped = a
		}

		if params.NameRegexp != "" {
			r, err := c.GetCompiledExpr(params.NameRegexp)
			require.NoError(t, err)
			if !r.MatchString(wrapped.Name) {
				continue
			}
		}

		if params.ScopeRegexp != "" {
			r, err := c.GetCompiledExpr(params.ScopeRegexp)
			require.NoError(t, err)
			if !r.MatchString(wrapped.Scope) {
				continue
			}
		}

		if params.VersionRegexp != "" {
			r, err := c.GetCompiledExpr(params.VersionRegexp)
			require.NoError(t, err)
			if !r.MatchString(wrapped.Version) {
				continue
			}
		}

		if len(params.IDs) > 0 {
			if !ss.Contains(namer.PolicyKey(wrapped.Policy)) {
				continue
			}
		}

		filtered = append(filtered, p)
	}

	return filtered
}

func WriteGoldenFile(t *testing.T, path string, contents proto.Message) {
	t.Helper()

	var b bytes.Buffer
	require.NoError(t, json.Indent(&b, []byte(protojson.Format(contents)), "", "  "), "Failed to JSON-encode golden file contents")
	b.WriteByte('\n')
	require.NoError(t, os.WriteFile(path, b.Bytes(), 0o644), "Failed to write golden file") //nolint:mnd,gosec
}
