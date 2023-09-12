// Copyright 2021-2023 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package validator

import (
	"fmt"

	"github.com/bufbuild/protovalidate-go"
	"go.uber.org/zap"
	"google.golang.org/protobuf/proto"

	requestv1 "github.com/cerbos/cerbos/api/genpb/cerbos/request/v1"
)

var Validator *protovalidate.Validator

func init() {
	var err error
	if Validator, err = Init(); err != nil {
		zap.L().Fatal(err.Error())
	}
}

func Init() (*protovalidate.Validator, error) {
	v, err := protovalidate.New(
		protovalidate.WithMessages(
			&requestv1.CheckResourcesRequest{},
			&requestv1.PlanResourcesRequest{}),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create validator: %w", err)
	}

	return v, nil
}

func Validate(msg proto.Message) error {
	return Validator.Validate(msg)
}
