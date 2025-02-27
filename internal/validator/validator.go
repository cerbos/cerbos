// Copyright 2021-2025 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package validator

import (
	"github.com/bufbuild/protovalidate-go"
	"google.golang.org/protobuf/proto"
)

var Validator = validator(protovalidate.Validate)

// validator implements protovalidate.Validate interface.
type validator func(proto.Message) error

func (v validator) Validate(msg proto.Message) error {
	return v(msg)
}

func Validate(msg proto.Message) error {
	return protovalidate.Validate(msg)
}
