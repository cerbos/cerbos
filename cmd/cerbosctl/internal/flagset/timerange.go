// Copyright 2021-2024 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package flagset

import (
	"encoding/csv"
	"fmt"
	"strings"
	"time"

	"github.com/alecthomas/kong"

	"google.golang.org/protobuf/types/known/timestamppb"
)

type timerange struct {
	Values []*timestamppb.Timestamp
}

func (t *timerange) Decode(ctx *kong.DecodeContext) error {
	var tr string
	if err := ctx.Scan.PopValueInto("time range", &tr); err != nil {
		return err
	}

	r := csv.NewReader(strings.NewReader(tr))
	parts, err := r.Read()
	if err != nil {
		return err
	}

	if len(parts) < 1 || len(parts) > 2 {
		return fmt.Errorf("invalid time range [%s]", tr)
	}

	t.Values = make([]*timestamppb.Timestamp, 2) //nolint:mnd

	for i := 0; i < len(parts); i++ {
		parsedTime, err := time.Parse(time.RFC3339, parts[i])
		if err != nil {
			return fmt.Errorf("invalid timestamp [%s]: %w", parts[i], err)
		}
		t.Values[i] = timestamppb.New(parsedTime)
	}

	// default to current time if only one timestamp value is provided
	if len(parts) == 1 {
		t.Values[1] = timestamppb.Now()
	}

	return nil
}

func (t timerange) IsSet() bool {
	return len(t.Values) > 0
}
