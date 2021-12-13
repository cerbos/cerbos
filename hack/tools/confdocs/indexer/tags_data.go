package indexer

import (
	"errors"
	"fmt"
	"github.com/fatih/structtag"
	"strings"
)

var errTagNotExists = errors.New("tag doesn't exist")

const (
	keyRequired = "required"
	keyOptional = "optional"

	optionDefaultValue      = "defaultValue"
	optionMutuallyExclusive = "mutuallyExclusive"
	optionIgnore            = "ignore"
)

type TagsData struct {
	ConfOptions
	Name     string
	Required bool
}

type ConfOptions struct {
	DefaultValue      string
	MutuallyExclusive string
	Ignore            bool
}

func ParseTags(tags string) (*TagsData, error) {
	t, err := structtag.Parse(tags)
	if err != nil {
		return nil, fmt.Errorf("failed to parse tags %w", err)
	}

	if t == nil {
		return nil, errTagNotExists
	}

	yamlTag, err := t.Get("yaml")
	if err != nil {
		return nil, errTagNotExists
	}

	var isRequired = false
	var confOptions ConfOptions
	confTag, _ := t.Get("conf")
	if confTag != nil {
		if confTag.Name == keyRequired {
			isRequired = true
		} else if confTag.Name == keyOptional {
			isRequired = false
		}
		confOptions = parseConfOptions(confTag.Options)
	}

	return &TagsData{
		ConfOptions: confOptions,
		Name:        yamlTag.Name,
		Required:    isRequired,
	}, nil
}

func parseConfOptions(options []string) ConfOptions {
	var confOptions = ConfOptions{}
	for _, option := range options {
		sp := strings.SplitN(option, "=", 2)

		switch sp[0] {
		case optionDefaultValue:
			confOptions.DefaultValue = sp[1]
			break
		case optionMutuallyExclusive:
			// TODO(oguzhan): Implement mutually exclusive option
			confOptions.MutuallyExclusive = sp[1]
			break
		case optionIgnore:
			confOptions.Ignore = true
		}
	}

	return confOptions
}
