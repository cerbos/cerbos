// +build tests

package test

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	policyv1 "github.com/cerbos/cerbos/internal/genpb/policy/v1"
	"github.com/cerbos/cerbos/internal/observability/logging"
	"github.com/cerbos/cerbos/internal/policy"
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
func LoadTestCases(t *testing.T, subDir string) []Case {
	t.Helper()

	dir := PathToDir(t, subDir)

	entries, err := filepath.Glob(filepath.Join(dir, "*.yaml"))
	require.NoError(t, err)

	testCases := make([]Case, len(entries))

	for i, entry := range entries {
		testCases[i] = Case{
			Name:  strings.TrimSuffix(filepath.Base(entry), filepath.Ext(entry)),
			Input: readFileContents(t, entry),
		}

		wantedFiles, err := filepath.Glob(fmt.Sprintf("%s.*", entry))
		require.NoError(t, err)

		testCases[i].Want = make(map[string][]byte, len(wantedFiles))

		for _, wanted := range wantedFiles {
			key := strings.TrimPrefix(filepath.Ext(wanted), ".")
			testCases[i].Want[key] = readFileContents(t, wanted)
		}
	}

	sort.SliceStable(testCases, func(i, j int) bool {
		return testCases[i].Name < testCases[j].Name
	})

	return testCases
}

func readFileContents(t *testing.T, filePath string) []byte {
	t.Helper()

	if _, err := os.Stat(filePath); err == nil {
		b, err := os.ReadFile(filePath)
		if err != nil {
			t.Errorf("Failed to read %s: %w", filePath, err)
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
