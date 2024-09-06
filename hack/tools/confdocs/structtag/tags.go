// Copyright (c) 2017, Fatih Arslan

//go:build confdocs
// +build confdocs

package structtag

import (
	"errors"
	"fmt"
	"strconv"

	"github.com/go-andiamo/splitter"
)

var (
	errTagSyntax      = errors.New("bad syntax for struct tag pair")
	errTagKeySyntax   = errors.New("bad syntax for struct tag key")
	errTagValueSyntax = errors.New("bad syntax for struct tag value")
	errTagNotExist    = errors.New("tag does not exist")
)

type Tags struct {
	tags []*Tag
}

type Tag struct {
	Key     string
	Name    string
	Options []string
}

func Parse(tag string) (*Tags, error) {
	var tags []*Tag

	hasTag := tag != ""
	for tag != "" {
		i := 0
		for i < len(tag) && tag[i] == ' ' {
			i++
		}
		tag = tag[i:]
		if tag == "" {
			break
		}

		i = 0
		for i < len(tag) && tag[i] > ' ' && tag[i] != ':' && tag[i] != '"' && tag[i] != 0x7f {
			i++
		}

		if i == 0 {
			return nil, errTagKeySyntax
		}
		if i+1 >= len(tag) || tag[i] != ':' {
			return nil, errTagSyntax
		}
		if tag[i+1] != '"' {
			return nil, errTagValueSyntax
		}

		key := tag[:i]
		tag = tag[i+1:]

		i = 1
		for i < len(tag) && tag[i] != '"' {
			if tag[i] == '\\' {
				i++
			}
			i++
		}
		if i >= len(tag) {
			return nil, errTagValueSyntax
		}

		qvalue := tag[:i+1]
		tag = tag[i+1:]

		value, err := strconv.Unquote(qvalue)
		if err != nil {
			return nil, errTagValueSyntax
		}

		split, err := splitter.NewSplitter(',', splitter.SquareBrackets)
		if err != nil {
			return nil, fmt.Errorf("failed to create a new splitter: %w", err)
		}

		res, err := split.Split(value)
		if err != nil {
			return nil, fmt.Errorf("failed to split value %s: %w", value, err)
		}

		name := res[0]
		options := res[1:]
		if len(options) == 0 {
			options = nil
		}

		tags = append(tags, &Tag{
			Key:     key,
			Name:    name,
			Options: options,
		})
	}

	if hasTag && len(tags) == 0 {
		return nil, nil
	}

	return &Tags{
		tags: tags,
	}, nil
}

func (t *Tags) Get(key string) (*Tag, error) {
	for _, tag := range t.tags {
		if tag.Key == key {
			return tag, nil
		}
	}

	return nil, errTagNotExist
}
