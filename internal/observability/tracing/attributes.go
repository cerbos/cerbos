// Copyright 2021 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package tracing

import "go.opentelemetry.io/otel/attribute"

const (
	requestIDKey     = attribute.Key("cerbos.request.id")
	reqResourceIDKey = attribute.Key("cerbos.request.resource_id")
	policyFQNKey     = attribute.Key("cerbos.policy.fqn")
)

var (
	RequestID     = requestIDKey.String
	ReqResourceID = reqResourceIDKey.String
	PolicyFQN     = policyFQNKey.String
)
