// Copyright 2021-2026 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package validator

import (
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"

	"buf.build/go/protovalidate"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
)

var Validator = validator(protovalidate.Validate)

// validator implements protovalidate.Validate interface.
type validator func(proto.Message, ...protovalidate.ValidationOption) error

func (v validator) Validate(msg proto.Message, options ...protovalidate.ValidationOption) error {
	err := v(msg, options...)

	var validationErr *protovalidate.ValidationError
	if !errors.As(err, &validationErr) {
		return err
	}

	for _, violation := range validationErr.Violations {
		if violation.RuleDescriptor != nil && violation.RuleDescriptor.FullName() == "buf.validate.EnumRules.in" {
			allValues := violation.FieldDescriptor.Enum().Values()
			allowedValues := violation.RuleValue.List()

			allowedNames := make([]string, allowedValues.Len())
			for i := range allowedValues.Len() {
				number := allowedValues.Get(i).Int()
				desc := allValues.ByNumber(protoreflect.EnumNumber(number))
				if desc == nil {
					allowedNames[i] = strconv.FormatInt(number, 10)
				} else {
					allowedNames[i] = string(desc.Name())
				}
			}

			slices.Sort(allowedNames)
			violation.Proto.Message = proto.String(fmt.Sprintf("must be one of [%s]", strings.Join(allowedNames, ", ")))
		}
	}

	return validationErr
}

func Validate(msg proto.Message, options ...protovalidate.ValidationOption) error {
	return Validator.Validate(msg, options...)
}
