// Copyright 2021-2026 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package validator

import (
	"buf.build/go/protovalidate"
	"google.golang.org/protobuf/proto"
)

var Validator = validator(protovalidate.Validate)

// validator implements protovalidate.Validate interface.
type validator func(proto.Message, ...protovalidate.ValidationOption) error

func (v validator) Validate(msg proto.Message, options ...protovalidate.ValidationOption) error {
	return v(msg, options...)
}

func Validate(msg proto.Message, options ...protovalidate.ValidationOption) error {
	return protovalidate.Validate(msg, options...)
}
