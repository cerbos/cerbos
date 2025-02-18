// Copyright 2021-2025 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package validator

import (
	"sync"

	"github.com/bufbuild/protovalidate-go"
	"go.uber.org/zap"
	"google.golang.org/protobuf/proto"

	policyv1 "github.com/cerbos/cerbos/api/genpb/cerbos/policy/v1"
	requestv1 "github.com/cerbos/cerbos/api/genpb/cerbos/request/v1"
)

var Validator = sync.OnceValue(func() protovalidate.Validator {
	validator, err := protovalidate.New(
		protovalidate.WithMessages(
			&policyv1.Policy{},
			&requestv1.CheckResourcesRequest{},
			&requestv1.PlanResourcesRequest{}),
	)
	if err != nil {
		zap.L().Fatal(err.Error())
	}

	return validator
})

func Validate(msg proto.Message) error {
	return Validator().Validate(msg)
}
