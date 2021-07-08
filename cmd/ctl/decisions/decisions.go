// Copyright 2021 Zenauth Ltd.

package decisions

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"sync"
	"time"

	"github.com/alecthomas/chroma"
	"github.com/alecthomas/chroma/formatters"
	"github.com/alecthomas/chroma/lexers"
	"github.com/alecthomas/chroma/styles"
	"github.com/gdamore/tcell/v2"
	"github.com/rivo/tview"
	"github.com/spf13/cobra"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"

	"github.com/cerbos/cerbos/cmd/ctl/audit"
	auditv1 "github.com/cerbos/cerbos/internal/genpb/audit/v1"
	requestv1 "github.com/cerbos/cerbos/internal/genpb/request/v1"
	responsev1 "github.com/cerbos/cerbos/internal/genpb/response/v1"
	svcv1 "github.com/cerbos/cerbos/internal/genpb/svc/v1"
)

const batchSize = 20

var auditFilterFlags = audit.NewAuditFilterDef()

type clientGenFunc func() (svcv1.CerbosAdminServiceClient, error)

func NewDecisionsCmd(clientGen clientGenFunc) *cobra.Command {
	cmd := &cobra.Command{
		Use:     "decisions",
		Short:   "Explore Cerbos engine decision logs",
		PreRunE: checkDecisionsFlags,
		RunE:    runDecisionsCmd(clientGen),
	}

	cmd.Flags().AddFlagSet(auditFilterFlags.FlagSet())

	return cmd
}

func checkDecisionsFlags(_ *cobra.Command, _ []string) error {
	return auditFilterFlags.Validate()
}

func runDecisionsCmd(clientGen clientGenFunc) func(*cobra.Command, []string) error {
	return func(cmd *cobra.Command, _ []string) error {
		client, err := clientGen()
		if err != nil {
			return err
		}

		req := auditFilterFlags.BuildRequest(requestv1.ListAuditLogEntriesRequest_KIND_DECISION)
		resp, err := client.ListAuditLogEntries(context.Background(), req)
		if err != nil {
			return err
		}

		var entries []*auditv1.DecisionLogEntry
		for {
			entry, err := resp.Recv()
			if err != nil {
				if errors.Is(err, io.EOF) {
					break
				}

				return err
			}

			decisionEntry, ok := entry.Entry.(*responsev1.ListAuditLogEntriesResponse_DecisionLogEntry)
			if !ok {
				continue
			}

			entries = append(entries, decisionEntry.DecisionLogEntry)
		}

		ui := mkUI(entries)
		return ui.Start()
	}
}

const (
	browserKey = "browser"
	detailsKey = "details"
)

type decisionsUI struct {
	app     *tview.Application
	tabs    *tview.Pages
	browser *browserPanel
	details *detailsPanel
}

type browserPanel struct {
	mu           sync.RWMutex
	entries      []*auditv1.DecisionLogEntry
	entriesTable *tview.Table
	jsonView     *tview.TextView
	info         *tview.TextView
}

type detailsPanel struct {
	inputsList    *tview.List
	principalView *tview.TextView
	resourceView  *tview.TextView
	actionsTable  *tview.Table
}

func mkUI(entries []*auditv1.DecisionLogEntry) *decisionsUI {
	ui := &decisionsUI{}

	ui.app = tview.NewApplication()
	ui.tabs = tview.NewPages()

	mkBrowserPanel(ui, entries)
	mkDetailsPanel(ui)

	ui.app.SetRoot(ui.tabs, true)
	ui.app.SetInputCapture(func(evt *tcell.EventKey) *tcell.EventKey {
		if evt.Key() == tcell.KeyRune {
			if r := evt.Rune(); r == 'q' || r == 'Q' {
				ui.app.Stop()
				return nil
			}
		}

		return evt
	})

	return ui
}

//nolint:gomnd
func mkBrowserPanel(ui *decisionsUI, entries []*auditv1.DecisionLogEntry) {
	ui.browser = &browserPanel{
		entriesTable: tview.NewTable().
			SetFixed(1, 0).
			SetBorders(false).
			SetSeparator(tview.Borders.Vertical).
			SetSelectable(true, false).
			SetDoneFunc(func(key tcell.Key) {
				if key == tcell.KeyTab {
					ui.app.SetFocus(ui.browser.jsonView)
					ui.browser.jsonView.SetBorderAttributes(tcell.AttrBold).SetBorderColor(tcell.ColorYellow)
					ui.browser.entriesTable.SetBorderAttributes(tcell.AttrNone).SetBorderColor(tcell.ColorDefault)
				}
			}),
		jsonView: tview.NewTextView().
			SetDynamicColors(true).
			SetDoneFunc(func(key tcell.Key) {
				if key == tcell.KeyTab {
					ui.app.SetFocus(ui.browser.entriesTable)
					ui.browser.entriesTable.SetBorderAttributes(tcell.AttrBold).SetBorderColor(tcell.ColorYellow)
					ui.browser.jsonView.SetBorderAttributes(tcell.AttrNone).SetBorderColor(tcell.ColorDefault)
				}
			}),
	}

	ui.browser.entriesTable.SetBorder(true)
	ui.browser.jsonView.SetBorder(true)

	populateEntriesTable(ui, entries)

	ui.browser.info = tview.NewTextView().
		SetDynamicColors(true).
		SetWrap(false)

	fmt.Fprintf(ui.browser.info, `[darkcyan]⭾[white] Switch between panes  [darkcyan]↑↓[white] Scroll  [darkcyan]⏎[white] View details  [darkcyan]q[white] Exit`)

	layout := tview.NewGrid().
		SetColumns(-1, -1).
		SetRows(0, 1).
		SetBorders(false).
		AddItem(ui.browser.entriesTable, 0, 0, 1, 1, 0, 0, true).
		AddItem(ui.browser.jsonView, 0, 1, 1, 1, 0, 0, false).
		AddItem(ui.browser.info, 1, 0, 1, 2, 1, 1, false)

	ui.tabs.AddPage(browserKey, layout, true, true)
}

//nolint:gomnd
func populateEntriesTable(ui *decisionsUI, entries []*auditv1.DecisionLogEntry) {
	ui.browser.entriesTable.SetCell(0, 0, tview.NewTableCell("ID").SetAlign(tview.AlignCenter).SetAttributes(tcell.AttrBold))
	ui.browser.entriesTable.SetCell(0, 1, tview.NewTableCell("Timestamp").SetAlign(tview.AlignCenter).SetAttributes(tcell.AttrBold))
	ui.browser.entriesTable.SetCell(0, 2, tview.NewTableCell("Address").SetAlign(tview.AlignCenter).SetAttributes(tcell.AttrBold))
	ui.browser.entriesTable.SetCell(0, 3, tview.NewTableCell("User Agent").SetAlign(tview.AlignCenter).SetAttributes(tcell.AttrBold))
	ui.browser.entriesTable.SetCell(0, 4, tview.NewTableCell("Forwarded For").SetAlign(tview.AlignCenter).SetAttributes(tcell.AttrBold))

	rowIndex := 1
	for _, entry := range entries {
		ui.browser.entriesTable.SetCell(rowIndex, 0, tview.NewTableCell(entry.CallId).SetReference(entry))
		ui.browser.entriesTable.SetCell(rowIndex, 1, tview.NewTableCell(entry.Timestamp.AsTime().Format(time.RFC3339)))
		ui.browser.entriesTable.SetCell(rowIndex, 2, tview.NewTableCell(entry.Peer.Address))
		ui.browser.entriesTable.SetCell(rowIndex, 3, tview.NewTableCell(entry.Peer.UserAgent))
		ui.browser.entriesTable.SetCell(rowIndex, 4, tview.NewTableCell(entry.Peer.ForwardedFor))
		rowIndex++
	}

	printer := newPrettyJSON()
	ui.browser.entriesTable.SetSelectionChangedFunc(func(row, _ int) {
		ui.browser.jsonView.Clear()

		col := ui.browser.entriesTable.GetCell(row, 0)
		entryRef := col.GetReference()

		if entry, ok := entryRef.(*auditv1.DecisionLogEntry); ok {
			printer.write(tview.ANSIWriter(ui.browser.jsonView), entry)
		}
	})
}

//nolint:gomnd
func mkDetailsPanel(ui *decisionsUI) {
	ui.details = &detailsPanel{
		inputsList:    tview.NewList(),
		principalView: tview.NewTextView().SetDynamicColors(true),
		resourceView:  tview.NewTextView().SetDynamicColors(true),
		actionsTable:  tview.NewTable(),
	}

	layout := tview.NewFlex().
		AddItem(ui.details.inputsList, 0, 1, true).
		AddItem(tview.NewFlex().
			SetDirection(tview.FlexRow).
			AddItem(ui.details.principalView, 0, 2, false).
			AddItem(ui.details.resourceView, 0, 2, false).
			AddItem(ui.details.actionsTable, 0, 1, false), 0, 1, false)

	ui.tabs.AddPage(detailsKey, layout, true, false)
}

func (d *decisionsUI) Start() error {
	return d.app.EnableMouse(true).Run()
}

type prettyJSON struct {
	lexer     chroma.Lexer
	formatter chroma.Formatter
	style     *chroma.Style
}

func newPrettyJSON() *prettyJSON {
	lexer := lexers.Get("json")
	if lexer == nil {
		lexer = lexers.Fallback
	}

	return &prettyJSON{
		lexer:     chroma.Coalesce(lexer),
		formatter: formatters.TTY16m,
		style:     styles.Monokai,
	}
}

func (p *prettyJSON) write(out io.Writer, msg proto.Message) {
	w := bufio.NewWriter(out)
	defer w.Flush()

	iterator, err := p.lexer.Tokenise(nil, protojson.Format(msg))
	if err != nil {
		w.WriteString(fmt.Sprintf("Error tokenising JSON: %v", err))
		return
	}

	if err := p.formatter.Format(w, p.style, iterator); err != nil {
		w.WriteString(fmt.Sprintf("Error printing JSON: %v", err))
	}
}
