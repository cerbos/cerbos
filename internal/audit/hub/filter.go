// Copyright 2021-2024 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package hub

import (
	"fmt"

	logsv1 "github.com/cerbos/cloud-api/genpb/cerbos/cloud/logs/v1"
	"github.com/ohler55/ojg/jp"
	"github.com/ohler55/ojg/oj"
	"go.uber.org/multierr"
	"google.golang.org/protobuf/encoding/protojson"
)

const (
	// TODO(saml) profile alternative prefixes? Separate, static entries for each log type perhaps
	// both log types.
	unionedPathPrefix = "$.entries[*][*]"
	peerPrefix        = unionedPathPrefix + ".peer"
	metadataPrefix    = unionedPathPrefix + ".metadata"

	checkResourcesDeprecatedPrefix = "$.entries[*].decisionLogEntry"
	checkResourcesPrefix           = "$.entries[*].decisionLogEntry.checkResources"
	planResourcesPrefix            = "$.entries[*].decisionLogEntry.planResources"
)

type AuditLogFilter struct {
	exprs []jp.Expr
}

func NewAuditLogFilter(conf MaskConf) (*AuditLogFilter, error) {
	expr, err := parseJSONPathExprs(conf)
	if err != nil {
		return nil, err
	}

	return &AuditLogFilter{
		exprs: expr,
	}, nil
}

func parseJSONPathExprs(conf MaskConf) (exprs []jp.Expr, outErr error) {
	// len(conf.CheckResources)*2 caters for two required rules
	// (deprecated base level inputs/outputs, and nested inside `check_resources`)
	nExpressions := len(conf.Peer) + len(conf.Metadata) + len(conf.CheckResources)*2 + len(conf.PlanResources)
	if nExpressions == 0 {
		return exprs, nil
	}

	exprs = make([]jp.Expr, nExpressions)

	i := 0
	parse := func(rule string) error {
		e, err := jp.ParseString(rule)
		if err != nil {
			return err
		}

		exprs[i] = e
		i++
		return nil
	}

	for _, r := range conf.Peer {
		if err := parse(fmt.Sprintf("%s.%s", peerPrefix, r)); err != nil {
			outErr = multierr.Append(outErr, err)
		}
	}

	for _, r := range conf.Metadata {
		if err := parse(fmt.Sprintf("%s.%s", metadataPrefix, r)); err != nil {
			outErr = multierr.Append(outErr, err)
		}
	}

	for _, r := range conf.CheckResources {
		if err := parse(fmt.Sprintf("%s.%s", checkResourcesPrefix, r)); err != nil {
			outErr = multierr.Append(outErr, err)
		}

		if err := parse(fmt.Sprintf("%s.%s", checkResourcesDeprecatedPrefix, r)); err != nil {
			outErr = multierr.Append(outErr, err)
		}
	}

	for _, r := range conf.PlanResources {
		if err := parse(fmt.Sprintf("%s.%s", planResourcesPrefix, r)); err != nil {
			outErr = multierr.Append(outErr, err)
		}
	}

	return exprs, outErr
}

func (f *AuditLogFilter) Filter(ingestBatch *logsv1.IngestBatch) (*logsv1.IngestBatch, error) {
	if len(f.exprs) == 0 {
		return ingestBatch, nil
	}

	jsonBytes, err := protojson.Marshal(ingestBatch)
	if err != nil {
		return nil, err
	}

	obj, err := oj.Parse(jsonBytes)
	if err != nil {
		return nil, err
	}

	for _, x := range f.exprs {
		if err := x.Del(obj); err != nil {
			return nil, err
		}
	}

	maskedBytes, err := oj.Marshal(obj)
	if err != nil {
		return nil, err
	}

	entry := &logsv1.IngestBatch{}
	if err := protojson.Unmarshal(maskedBytes, entry); err != nil {
		return nil, err
	}

	return entry, nil
}
