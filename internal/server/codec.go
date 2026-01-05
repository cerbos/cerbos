// Copyright 2021-2026 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"fmt"

	vtgrpc "github.com/planetscale/vtprotobuf/codec/grpc"
	"google.golang.org/grpc/encoding"

	// Import the default grpc encoding to ensure that it gets replaced by this codec.
	"google.golang.org/grpc/encoding/gzip"
	_ "google.golang.org/grpc/encoding/proto"
	"google.golang.org/protobuf/proto"
)

const name = "proto"

func init() {
	// Register the codec to use VT where possible for optimized marshaling/unmarshaling.
	encoding.RegisterCodec(Codec{vtcodec: vtgrpc.Codec{}})
	// Register gzip compressor.
	encoding.RegisterCompressor(encoding.GetCompressor(gzip.Name))
}

// Codec implements the grpc Codec interface to delegate encoding to VT where possible.
type Codec struct {
	vtcodec vtgrpc.Codec
}

func (c Codec) Name() string {
	return name
}

func (c Codec) Marshal(v any) ([]byte, error) {
	if b, err := c.vtcodec.Marshal(v); err == nil {
		return b, nil
	}

	vv, ok := v.(proto.Message)
	if !ok {
		return nil, fmt.Errorf("failed to marshal, message is %T, want proto.Message", v)
	}
	return proto.Marshal(vv)
}

func (c Codec) Unmarshal(data []byte, v any) error {
	if err := c.vtcodec.Unmarshal(data, v); err == nil {
		return nil
	}

	vv, ok := v.(proto.Message)
	if !ok {
		return fmt.Errorf("failed to unmarshal, message is %T, want proto.Message", v)
	}
	return proto.Unmarshal(data, vv)
}
