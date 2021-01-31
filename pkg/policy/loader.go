package policy

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"io/ioutil"
	"unicode"

	"github.com/ghodss/yaml"
	"google.golang.org/protobuf/encoding/protojson"

	policyv1 "github.com/charithe/menshen/pkg/generated/policy/v1"
)

// LoadPolicy reads a policy from the given reader.
func LoadPolicy(src io.Reader) (*policyv1.Policy, error) {
	jsonBytes, err := toJSON(src)
	if err != nil {
		return nil, fmt.Errorf("failed to convert stream to JSON: %w", err)
	}

	var policy policyv1.Policy
	if err := protojson.Unmarshal(jsonBytes, &policy); err != nil {
		return nil, fmt.Errorf("failed to unmarshal JSON: %w", err)
	}

	return &policy, nil
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
