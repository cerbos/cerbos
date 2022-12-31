// Copyright 2021-2023 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package internal

import (
	"github.com/cerbos/cerbos/internal/compile"
	"google.golang.org/protobuf/types/known/emptypb"
)

type ProtoSet map[string]*emptypb.Empty

type StringSet map[string]struct{}

func ToSet(values []string) StringSet {
	s := make(StringSet, len(values))
	for _, v := range values {
		s[v] = struct{}{}
	}

	return s
}

func SetIntersects(s1 ProtoSet, s2 StringSet) bool {
	for v := range s1 {
		if v == compile.AnyRoleVal {
			return true
		}

		if _, ok := s2[v]; ok {
			return true
		}
	}

	return false
}
