package policy

import (
	"bytes"
	"fmt"
	"io"
	"unicode"

	"github.com/ghodss/yaml"
	"google.golang.org/protobuf/encoding/protojson"

	policyv1 "github.com/charithe/menshen/pkg/generated/policy/v1"
)

// ReadPolicy reads a policy from the given reader and returns it along with the checksum.
func ReadPolicy(src io.Reader) (*policyv1.Policy, error) {
	data, err := io.ReadAll(src)
	if err != nil {
		return nil, fmt.Errorf("failed to read policy: %w", err)
	}

	jsonBytes, err := toJSON(data)
	if err != nil {
		return nil, fmt.Errorf("failed to convert policy to JSON: %w", err)
	}

	policy := &policyv1.Policy{}
	if err := protojson.Unmarshal(jsonBytes, policy); err != nil {
		return nil, fmt.Errorf("failed to unmarshal JSON: %w", err)
	}

	return policy, nil
}

func toJSON(data []byte) ([]byte, error) {
	trimmed := bytes.TrimLeftFunc(data, unicode.IsSpace)

	// If we find a starting brace, this already contains JSON.
	if bytes.HasPrefix(trimmed, []byte("{")) {
		return trimmed, nil
	}

	return yaml.YAMLToJSON(trimmed)
}

func WritePolicy(dest io.Writer, p *policyv1.Policy) error {
	jsonBytes, err := protojson.Marshal(p)
	if err != nil {
		return fmt.Errorf("failed to marshal policy: %w", err)
	}

	yamlBytes, err := yaml.JSONToYAML(jsonBytes)
	if err != nil {
		return fmt.Errorf("failed to convert policy to YAML: %w", err)
	}

	if _, err := io.Copy(dest, bytes.NewReader(yamlBytes)); err != nil {
		return fmt.Errorf("failed to write policy: %w", err)
	}

	return nil
}
