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
				m.MarshalAccessLogEntry(rec)
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
				m.MarshalDecisionLogEntry(rec)
			}
		})
	}
}
