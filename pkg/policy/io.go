package policy

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"io"
	"io/ioutil"
	"unicode"

	"github.com/ghodss/yaml"
	"google.golang.org/protobuf/encoding/protojson"

	policyv1 "github.com/charithe/menshen/pkg/generated/policy/v1"
)

type Checksum []byte

// ReadPolicy reads a policy from the given reader and returns it along with the checksum.
func ReadPolicy(src io.Reader) (*policyv1.Policy, Checksum, error) {
	data, checksum, err := readWithChecksum(src)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to read policy: %w", err)
	}

	jsonBytes, err := toJSON(data)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to convert policy to JSON: %w", err)
	}

	policy := &policyv1.Policy{}
	if err := protojson.Unmarshal(jsonBytes, policy); err != nil {
		return nil, nil, fmt.Errorf("failed to unmarshal JSON: %w", err)
	}

	return policy, checksum, policy.Validate()
}

func readWithChecksum(src io.Reader) ([]byte, Checksum, error) {
	h := sha256.New()
	r := io.TeeReader(src, h)

	data, err := ioutil.ReadAll(r)
	if err != nil {
		return nil, nil, err
	}

	return data, h.Sum(nil), nil
}

func toJSON(data []byte) ([]byte, error) {
	trimmed := bytes.TrimLeftFunc(data, unicode.IsSpace)

	// If we find a starting brace, this already contains JSON.
	if bytes.HasPrefix(trimmed, []byte("{")) {
		return trimmed, nil
	}

	return yaml.YAMLToJSON(trimmed)
}

func WritePolicy(dest io.Writer, p *policyv1.Policy) (Checksum, error) {
	jsonBytes, err := protojson.Marshal(p)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal policy: %w", err)
	}

	yamlBytes, err := yaml.JSONToYAML(jsonBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to convert policy to YAML: %w", err)
	}

	return writeWithChecksum(dest, yamlBytes)
}

func writeWithChecksum(dest io.Writer, data []byte) (Checksum, error) {
	h := sha256.New()
	w := io.MultiWriter(dest, h)

	_, err := io.Copy(w, bytes.NewReader(data))
	if err != nil {
		return nil, err
	}

	return h.Sum(nil), nil
}
