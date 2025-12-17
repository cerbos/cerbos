// Copyright 2021-2025 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package types

import (
	"github.com/google/cel-go/common/types"
	"google.golang.org/protobuf/proto"
)

func MessageType[T proto.Message]() *types.Type {
	var message T
	return types.NewObjectType(string(message.ProtoReflect().Descriptor().FullName()))
}
