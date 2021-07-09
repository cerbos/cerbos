// Copyright 2021 Zenauth Ltd.

package audit

import (
	"encoding/csv"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/spf13/pflag"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/timestamppb"

	requestv1 "github.com/cerbos/cerbos/internal/genpb/request/v1"
)

var errMoreThanOneFilter = errors.New("more than one filter specified: choose from either `tail`, `between`, `since` or `lookup`")

type FilterDef struct {
	tail    uint16
	between timerangeFlag
	since   time.Duration
	lookup  string
}

func NewFilterDef() *FilterDef {
	return &FilterDef{}
}

func (afd *FilterDef) FlagSet() *pflag.FlagSet {
	fs := pflag.NewFlagSet("filters", pflag.ExitOnError)
	fs.Uint16Var(&afd.tail, "tail", 0, "View last N entries")
	fs.Var(&afd.between, "between", "View entries between two timestamps")
	fs.DurationVar(&afd.since, "since", 0, "View entries from last N hours/minutes")
	fs.StringVar(&afd.lookup, "lookup", "", "View by call ID")

	return fs
}

func (afd *FilterDef) Validate() error {
	filterCount := 0
	if afd.tail > 0 {
		filterCount++
	}

	if afd.between.isSet() {
		filterCount++
	}

	if afd.since > 0 {
		filterCount++
	}

	if afd.lookup != "" {
		filterCount++
	}

	if filterCount > 1 {
		return errMoreThanOneFilter
	}

	return nil
}

func (afd *FilterDef) BuildRequest(kind requestv1.ListAuditLogEntriesRequest_Kind) *requestv1.ListAuditLogEntriesRequest {
	req := &requestv1.ListAuditLogEntriesRequest{Kind: kind}

	switch {
	case afd.tail > 0:
		req.Filter = &requestv1.ListAuditLogEntriesRequest_Tail{Tail: uint32(afd.tail)}
	case afd.between.isSet():
		req.Filter = &requestv1.ListAuditLogEntriesRequest_Between{
			Between: &requestv1.ListAuditLogEntriesRequest_TimeRange{
				Start: afd.between.tsVals[0],
				End:   afd.between.tsVals[1],
			},
		}
	case afd.since > 0:
		req.Filter = &requestv1.ListAuditLogEntriesRequest_Since{Since: durationpb.New(afd.since)}
	case afd.lookup != "":
		req.Filter = &requestv1.ListAuditLogEntriesRequest_Lookup{Lookup: afd.lookup}
	}

	return req
}

type kindFlag requestv1.ListAuditLogEntriesRequest_Kind

func (kf kindFlag) Kind() requestv1.ListAuditLogEntriesRequest_Kind {
	return requestv1.ListAuditLogEntriesRequest_Kind(kf)
}

func (kf kindFlag) String() string {
	return "decision"
}

func (kf *kindFlag) Set(v string) error {
	switch strings.ToLower(v) {
	case "access":
		*kf = kindFlag(requestv1.ListAuditLogEntriesRequest_KIND_ACCESS)
		return nil
	case "decision":
		*kf = kindFlag(requestv1.ListAuditLogEntriesRequest_KIND_DECISION)
		return nil
	default:
		return fmt.Errorf("unknown kind [%s]: valid values are 'access' or 'decision'", v)
	}
}

func (kf kindFlag) Type() string {
	return "kindFlag"
}

type timerangeFlag struct {
	tsVals []*timestamppb.Timestamp
}

func (tf timerangeFlag) isSet() bool {
	return len(tf.tsVals) > 0
}

func (tf timerangeFlag) String() string {
	return ""
}

func (tf *timerangeFlag) Set(v string) error {
	r := csv.NewReader(strings.NewReader(v))
	parts, err := r.Read()
	if err != nil {
		return err
	}

	if len(parts) < 1 || len(parts) > 2 {
		return fmt.Errorf("invalid time range [%s]", v)
	}

	tf.tsVals = make([]*timestamppb.Timestamp, 2) //nolint:gomnd

	for i := 0; i < len(parts); i++ {
		t, err := time.Parse(time.RFC3339, parts[i])
		if err != nil {
			return fmt.Errorf("invalid timestamp [%s]: %w", parts[i], err)
		}
		tf.tsVals[i] = timestamppb.New(t)
	}

	// default to current time if only one timestamp value is provided
	if len(parts) == 1 {
		tf.tsVals[1] = timestamppb.Now()
	}

	return nil
}

func (tf timerangeFlag) Type() string {
	return "timerangeFlag"
}
