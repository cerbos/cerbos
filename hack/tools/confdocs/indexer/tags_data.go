package indexer

import (
	"errors"
	"fmt"
	"github.com/fatih/structtag"
)

var errTagNotExists = errors.New("tag doesn't exist")

type TagsData struct {
	Name string
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

	return &TagsData{
		Name: yamlTag.Name,
	}, nil
}
