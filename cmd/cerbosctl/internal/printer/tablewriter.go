// Copyright 2021-2025 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package printer

import (
	"io"

	"github.com/olekukonko/tablewriter"
)

func NewTableWriter(writer io.Writer) *tablewriter.Table {
	tw := tablewriter.NewWriter(writer)
	tw.SetAutoWrapText(false)
	tw.SetAutoFormatHeaders(true)
	tw.SetHeaderAlignment(tablewriter.ALIGN_LEFT)
	tw.SetAlignment(tablewriter.ALIGN_LEFT)
	tw.SetCenterSeparator("")
	tw.SetColumnSeparator("")
	tw.SetRowSeparator("")
	tw.SetHeaderLine(false)
	tw.SetBorder(false)
	tw.SetTablePadding("\t")
	tw.SetNoWhiteSpace(true)

	return tw
}
