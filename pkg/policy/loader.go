package policy

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
	"unicode"

	"github.com/ghodss/yaml"
	"go.uber.org/zap"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/reflect/protoreflect"

	policyv1 "github.com/charithe/menshen/pkg/generated/policy/v1"
	"github.com/charithe/menshen/pkg/internal"
)

var supportedFileTypes = map[string]struct{}{".yaml": {}, ".yml": {}, ".json": {}}

// LoadPolicies loads policies from the specified directory.
func LoadPolicies(dir string) (*internal.CompileResult, error) {
	var err error
	pset := &policyv1.PolicySet{}

	log := zap.S().Named("policy.loader")
	log.Infof("Loading policies from %s", dir)

	//TODO validate files
	pset.DerivedRoles, err = loadDerivedRoles(filepath.Join(dir, "derived_roles"))
	if err != nil {
		log.Errorw("Failed to load derived roles", "error", err)
		return nil, err
	}

	pset.ResourcePolicies, err = loadPolicies(filepath.Join(dir, "resource_policies"))
	if err != nil {
		log.Errorw("Failed to load resource policies", "error", err)
		return nil, err
	}

	pset.PrincipalPolicies, err = loadPolicies(filepath.Join(dir, "principal_policies"))
	if err != nil {
		log.Errorw("Failed to load principal policies", "error", err)
		return nil, err
	}

	return internal.Compile(pset)
}

func loadDerivedRoles(dir string) (map[string]*policyv1.DerivedRoles, error) {
	entries, err := ioutil.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("failed to read directory %s: %w", dir, err)
	}

	derivedRoles := make(map[string]*policyv1.DerivedRoles)

	for _, e := range entries {
		if !isSupportedFile(e) {
			continue
		}

		fileName := filepath.Join(dir, e.Name())

		dr := &policyv1.DerivedRoles{}
		if err := loadFromFile(fileName, dr); err != nil {
			return nil, fmt.Errorf("failed to read file %s: %w", fileName, err)
		}

		derivedRoles[fileName] = dr
	}

	return derivedRoles, nil
}

func loadPolicies(dir string) (map[string]*policyv1.Policy, error) {
	entries, err := ioutil.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("failed to read directory %s: %w", dir, err)
	}

	policies := make(map[string]*policyv1.Policy)

	for _, e := range entries {
		if !isSupportedFile(e) {
			continue
		}

		fileName := filepath.Join(dir, e.Name())

		p := &policyv1.Policy{}
		if err := loadFromFile(fileName, p); err != nil {
			return nil, fmt.Errorf("failed to read file %s: %w", fileName, err)
		}

		policies[fileName] = p
	}

	return policies, nil
}

func isSupportedFile(e os.FileInfo) bool {
	if e.IsDir() {
		return false
	}

	ext := strings.ToLower(filepath.Ext(e.Name()))
	_, exists := supportedFileTypes[ext]

	return exists
}

func loadFromFile(fileName string, out protoreflect.ProtoMessage) error {
	f, err := os.Open(fileName)
	if err != nil {
		return err
	}

	defer f.Close()

	return loadFromJSONOrYAML(f, out)
}

// LoadPolicy reads a policy from the given reader.
func LoadPolicy(src io.Reader) (*policyv1.Policy, error) {
	policy := &policyv1.Policy{}
	err := loadFromJSONOrYAML(src, policy)

	return policy, err
}

// LoadDerivedRoles reads derived roles from the given reader.
func LoadDerivedRoles(src io.Reader) (*policyv1.DerivedRoles, error) {
	dr := &policyv1.DerivedRoles{}
	err := loadFromJSONOrYAML(src, dr)

	return dr, err
}

func loadFromJSONOrYAML(src io.Reader, out protoreflect.ProtoMessage) error {
	jsonBytes, err := toJSON(src)
	if err != nil {
		return fmt.Errorf("failed to convert stream to JSON: %w", err)
	}

	if err := protojson.Unmarshal(jsonBytes, out); err != nil {
		return fmt.Errorf("failed to unmarshal JSON: %w", err)
	}

	return nil
}

func toJSON(src io.Reader) ([]byte, error) {
	buffer := bufio.NewReader(src)

	data, err := ioutil.ReadAll(buffer)
	if err != nil {
		return nil, err
	}

	trimmed := bytes.TrimLeftFunc(data, unicode.IsSpace)

	// If we find a starting brace, this already contains JSON.
	if bytes.HasPrefix(trimmed, []byte("{")) {
		return trimmed, nil
	}

	return yaml.YAMLToJSON(trimmed)
}
