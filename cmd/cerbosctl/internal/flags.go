// Copyright 2021-2022 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package internal

import (
	"encoding/csv"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/spf13/pflag"
	"google.golang.org/protobuf/types/known/timestamppb"

	requestv1 "github.com/cerbos/cerbos/api/genpb/cerbos/request/v1"
	"github.com/cerbos/cerbos/client"
)

var errMoreThanOneFilter = errors.New("more than one filter specified: choose from either `tail`, `between`, `since` or `lookup`")

type AuditLogFilterDef struct {
	lookup  string
	between timerangeFlag
	since   time.Duration
	tail    uint16
}

func NewAuditLogFilterDef() *AuditLogFilterDef {
	return &AuditLogFilterDef{}
}

func (afd *AuditLogFilterDef) FlagSet() *pflag.FlagSet {
	fs := pflag.NewFlagSet("filters", pflag.ExitOnError)
	fs.Uint16Var(&afd.tail, "tail", 0, "View last N entries")
	fs.Var(&afd.between, "between", "View entries between two timestamps")
	fs.DurationVar(&afd.since, "since", 0, "View entries from last N hours/minutes")
	fs.StringVar(&afd.lookup, "lookup", "", "View by call ID")

	return fs
}

func (afd *AuditLogFilterDef) Validate() error {
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

	if filterCount == 0 {
		afd.tail = 30
	}

	return nil
}

type KindFlag requestv1.ListAuditLogEntriesRequest_Kind

func (kf KindFlag) Kind() requestv1.ListAuditLogEntriesRequest_Kind {
	return requestv1.ListAuditLogEntriesRequest_Kind(kf)
}

func (kf KindFlag) String() string {
	return "decision"
}

func (kf *KindFlag) Set(v string) error {
	switch strings.ToLower(v) {
	case "access":
		*kf = KindFlag(requestv1.ListAuditLogEntriesRequest_KIND_ACCESS)
		return nil
	case "decision":
		*kf = KindFlag(requestv1.ListAuditLogEntriesRequest_KIND_DECISION)
		return nil
	default:
		return fmt.Errorf("unknown kind [%s]: valid values are 'access' or 'decision'", v)
	}
}

func (kf KindFlag) Type() string {
	return "KindFlag"
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

func GenAuditLogOptions(filter *AuditLogFilterDef) client.AuditLogOptions {
	switch {
	case filter.tail > 0:
		return client.AuditLogOptions{
			Tail: uint32(filter.tail),
		}
	case filter.between.isSet():
		return client.AuditLogOptions{
			StartTime: filter.between.tsVals[0].AsTime(),
			EndTime:   filter.between.tsVals[1].AsTime(),
		}
	case filter.since > 0:
		return client.AuditLogOptions{
			StartTime: time.Now().Add(time.Duration(-1) * filter.since),
			EndTime:   time.Now(),
		}
	case filter.lookup != "":
		return client.AuditLogOptions{
			Lookup: filter.lookup,
		}
	default:
		return client.AuditLogOptions{}
	}
}

type ListPoliciesFilterDef struct {
	format  string
	kind    []string
	name    []string
	version []string
}

func NewListPoliciesFilterDef() *ListPoliciesFilterDef {
	return &ListPoliciesFilterDef{}
}

func (lpfd *ListPoliciesFilterDef) FlagSet() *pflag.FlagSet {
	fs := pflag.NewFlagSet("filters", pflag.ExitOnError)
	fs.StringVar(&lpfd.format, "format", "", "Output format for the policies; json, yaml formats are supported (leave empty for pretty output)")
	fs.StringSliceVar(&lpfd.kind, "kind", []string{}, "Filter policies by kind. Possible values are derived_roles, principal, resource")
	fs.StringSliceVar(&lpfd.name, "name", []string{}, "Filter policies by name.")
	fs.StringSliceVar(&lpfd.version, "version", []string{}, "Filter policies by version.")
	return fs
}

func (lpfd *ListPoliciesFilterDef) OutputFormat() string {
	return lpfd.format
}

func (lpfd *ListPoliciesFilterDef) Kind() []string {
	return lpfd.kind
}

func (lpfd *ListPoliciesFilterDef) Name() []string {
	return lpfd.name
}

func (lpfd *ListPoliciesFilterDef) Version() []string {
	return lpfd.version
}

type GetPolicyFilterDef struct {
	format string
}

func NewGetPolicyFilterDef() *GetPolicyFilterDef {
	return &GetPolicyFilterDef{}
}

func (gpfd *GetPolicyFilterDef) FlagSet() *pflag.FlagSet {
	fs := pflag.NewFlagSet("filters", pflag.ExitOnError)
	fs.StringVar(&gpfd.format, "format", "json", "Output format for the policies; json, yaml formats are supported")
	return fs
}

func (gpfd *GetPolicyFilterDef) OutputFormat() string {
	return gpfd.format
}
