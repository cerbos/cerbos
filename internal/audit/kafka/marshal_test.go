// Copyright 2021-2025 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package kafka

import (
	"fmt"
	"testing"

	auditv1 "github.com/cerbos/cerbos/api/genpb/cerbos/audit/v1"
)

var encoding = []Encoding{EncodingJSON, EncodingProtobuf}

func BenchmarkRecordMarshaller_AccessLog(b *testing.B) {
	for _, enc := range encoding {
		b.Run(fmt.Sprintf("encoding_%s", enc), func(b *testing.B) {
			m := newMarshaller(enc)
			rec := &auditv1.AccessLogEntry{
				CallId: "01ARZ3NDEKTSV4RRFFQ69G5FAV",
			}

			b.ResetTimer()
			b.ReportAllocs()

			for i := 0; i < b.N; i++ {
				if _, err := m.Marshal(rec, KindAccess); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func BenchmarkRecordMarshaller_DecisionLog(b *testing.B) {
	for _, enc := range encoding {
		b.Run(fmt.Sprintf("encoding_%s", enc), func(b *testing.B) {
			m := newMarshaller(enc)
			rec := &auditv1.DecisionLogEntry{
				CallId: "01ARZ3NDEKTSV4RRFFQ69G5FAV",
			}

			b.ResetTimer()
			b.ReportAllocs()

			for i := 0; i < b.N; i++ {
				if _, err := m.Marshal(rec, KindDecision); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
