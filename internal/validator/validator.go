// Copyright 2021-2024 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package validator

import (
	"github.com/bufbuild/protovalidate-go"
	"go.uber.org/zap"
	"google.golang.org/protobuf/proto"

	requestv1 "github.com/cerbos/cerbos/api/genpb/cerbos/request/v1"
)

var Validator *protovalidate.Validator

func init() {
	var err error
	if Validator, err = protovalidate.New(
		protovalidate.WithMessages(
			&requestv1.CheckResourcesRequest{},
			&requestv1.PlanResourcesRequest{}),
	); err != nil {
		zap.L().Fatal(err.Error())
	}
}

func Validate(msg proto.Message) error {
	return Validator.Validate(msg)
}
