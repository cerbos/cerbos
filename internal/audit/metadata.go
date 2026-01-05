// Copyright 2021-2026 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"context"
	"fmt"

	auditv1 "github.com/cerbos/cerbos/api/genpb/cerbos/audit/v1"
	"google.golang.org/grpc/metadata"
)

var alwaysExcludeMetadataKeys = map[string]struct{}{
	"authorization":  {},
	"grpc-trace-bin": {},
}

type MetadataExtractor func(context.Context) map[string]*auditv1.MetaValues

func NewMetadataExtractor() (MetadataExtractor, error) {
	conf, err := GetConf()
	if err != nil {
		return nil, fmt.Errorf("failed to read audit conf: %w", err)
	}

	return NewMetadataExtractorFromConf(conf), nil
}

func NewMetadataExtractorFromConf(conf *Conf) MetadataExtractor {
	if len(conf.ExcludeMetadataKeys) == 0 && len(conf.IncludeMetadataKeys) == 0 {
		return func(_ context.Context) map[string]*auditv1.MetaValues {
			return nil
		}
	}

	exclude := sliceToLookupMap(conf.ExcludeMetadataKeys)
	include := sliceToLookupMap(conf.IncludeMetadataKeys)

	var shouldInclude func(string) bool
	switch {
	case len(exclude) > 0 && len(include) == 0:
		shouldInclude = func(k string) bool {
			if _, ok := alwaysExcludeMetadataKeys[k]; ok {
				return false
			}

			_, ok := exclude[k]
			return !ok
		}
	case len(exclude) == 0 && len(include) > 0:
		shouldInclude = func(k string) bool {
			if _, ok := alwaysExcludeMetadataKeys[k]; ok {
				return false
			}

			_, ok := include[k]
			return ok
		}
	default:
		shouldInclude = func(k string) bool {
			if _, ok := alwaysExcludeMetadataKeys[k]; ok {
				return false
			}

			if _, ok := exclude[k]; ok {
				return false
			}

			_, ok := include[k]
			return ok
		}
	}

	return func(ctx context.Context) map[string]*auditv1.MetaValues {
		md, ok := metadata.FromIncomingContext(ctx)
		if !ok || len(md) == 0 {
			return nil
		}

		extracted := make(map[string]*auditv1.MetaValues, len(md))
		for key, values := range md {
			if !shouldInclude(key) {
				continue
			}

			extracted[key] = &auditv1.MetaValues{Values: values}
		}

		if len(extracted) == 0 {
			return nil
		}

		return extracted
	}
}

func sliceToLookupMap(slice []string) map[string]struct{} {
	m := make(map[string]struct{})
	for _, k := range slice {
		m[k] = struct{}{}
	}

	return m
}
