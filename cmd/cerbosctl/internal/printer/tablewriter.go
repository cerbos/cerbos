// Copyright 2021-2026 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package printer

import (
	"io"

	"github.com/olekukonko/tablewriter"
	"github.com/olekukonko/tablewriter/renderer"
	"github.com/olekukonko/tablewriter/tw"
)

func NewTableWriter(writer io.Writer) *tablewriter.Table {
	tableWriter := tablewriter.NewTable(
		writer,
		tablewriter.WithHeaderAutoFormat(tw.On),
		tablewriter.WithHeaderAlignment(tw.AlignLeft),
		tablewriter.WithPadding(tw.Padding{
			Left:  "",
			Right: "  ",
		}),
		tablewriter.WithRenderer(
			renderer.NewBlueprint(
				tw.Rendition{
					Borders: tw.BorderNone,
					Settings: tw.Settings{
						Separators: tw.SeparatorsNone,
						Lines:      tw.LinesNone,
					},
				},
			),
		),
		tablewriter.WithRowAlignment(tw.AlignLeft),
		tablewriter.WithRowAutoWrap(tw.WrapNone),
	)

	return tableWriter
}
