// Copyright 2021 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package writer

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

	optionDefaultValue = "defaultValue"
	optionIgnore       = "ignore"
)

type TagInfo struct {
	DefaultValue string
	Name         string
	Ignore       bool
	Required     bool
}

func parseTag(tag string) (*TagInfo, error) {
	t, err := structtag.Parse(tag[1 : len(tag)-1])
	if err != nil {
		return nil, fmt.Errorf("structtag failed to parse tags: %w", err)
	}

	if t == nil {
		return nil, errTagNotExists
	}

	yamlTag, err := t.Get("yaml")
	if err != nil {
		return nil, errTagNotExists
	}

	var isRequired = false
	var isIgnored = false
	var defaultValue = ""
	confTag, _ := t.Get("conf")
	if confTag != nil {
		if confTag.Name == keyRequired {
			isRequired = true
		} else if confTag.Name == keyOptional {
			isRequired = false
		}

		for _, option := range confTag.Options {
			sp := strings.SplitN(option, "=", 2)

			switch sp[0] {
			case optionDefaultValue:
				defaultValue = sp[1]
				break
			case optionIgnore:
				isIgnored = true
			}
		}
	}

	return &TagInfo{
		DefaultValue: defaultValue,
		Name:         yamlTag.Name,
		Ignore:       isIgnored,
		Required:     isRequired,
	}, nil
}
