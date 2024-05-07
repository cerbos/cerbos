// Copyright 2021-2024 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package decisions

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/alecthomas/kong"
	"github.com/cerbos/cerbos-sdk-go/cerbos"
	cmdclient "github.com/cerbos/cerbos/cmd/cerbosctl/internal/client"
	"github.com/cerbos/cerbos/cmd/cerbosctl/internal/flagset"

	"github.com/alecthomas/chroma/v2"
	"github.com/alecthomas/chroma/v2/formatters"
	"github.com/alecthomas/chroma/v2/lexers"
	"github.com/alecthomas/chroma/v2/styles"
	"github.com/gdamore/tcell/v2"
	"github.com/rivo/tview"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"

	auditv1 "github.com/cerbos/cerbos/api/genpb/cerbos/audit/v1"
	effectv1 "github.com/cerbos/cerbos/api/genpb/cerbos/effect/v1"
)

var help = `Requires audit logging to be enabled on the server. Supports several ways of filtering the data.

tail: View the last N records
between: View records captured between two timestamps. The timestamps must be formatted as ISO-8601
since: View records from X hours/minutes/seconds ago to now. Unit suffixes are: h=hours, m=minutes s=seconds
lookup: View a specific record using the Cerbos Call ID

# View the last 10 records
cerbosctl decisions --tail=10

# View the logs from midnight 2021-07-01 to midnight 2021-07-02
cerbosctl decisions --between=2021-07-01T00:00:00Z,2021-07-02T00:00:00Z

# View the logs from midnight 2021-07-01 to now
cerbosctl decisions --between=2021-07-01T00:00:00Z

# View the logs from 3 hours ago to now
cerbosctl decisions --since=3h --raw

# View a specific log entry by call ID
cerbosctl decisions--lookup=01F9Y5MFYTX7Y87A30CTJ2FB0S`

type Cmd struct {
	flagset.AuditFilters
}

func (c *Cmd) Run(_ *kong.Kong, ctx *cmdclient.Context) error {
	logOptions := c.AuditFilters.GenOptions()
	logOptions.Type = cerbos.DecisionLogs

	entries, err := ctx.AdminClient.AuditLogs(context.Background(), logOptions)
	if err != nil {
		return err
	}

	decisions := make([]*auditv1.DecisionLogEntry, 0)
	for entry := range entries {
		decisionEntry, err := entry.DecisionLog()
		if err != nil {
			return err
		}

		decisions = append(decisions, decisionEntry)
	}

	ui := mkUI(decisions)
	return ui.Start()
}

func (c *Cmd) Help() string {
	return help
}

func (c *Cmd) Validate() error {
	return c.AuditFilters.Validate()
}

const (
	browserKey      = "browser"
	checkDetailsKey = "checkDetails"
	planDetailsKey  = "planDetails"
)

type decisionsUI struct {
	app          *tview.Application
	tabs         *tview.Pages
	browser      *browserPanel
	checkDetails *checkDetailsPanel
	planDetails  *planDetailsPanel
}

type browserPanel struct {
	entriesTable *tview.Table
	jsonView     *tview.TextView
	focusOrder   []tview.Primitive
}

type checkDetailsPanel struct {
	inputsList       *tview.List
	principalView    *tview.TextView
	resourceView     *tview.TextView
	actionsTable     *tview.Table
	derivedRolesView *tview.TextView
	focusOrder       []tview.Primitive
}

type planDetailsPanel struct {
	principalView *tview.TextView
	resourceView  *tview.TextView
	planView      *tview.TextView
	debugView     *tview.TextView
	focusOrder    []tview.Primitive
}

func mkUI(entries []*auditv1.DecisionLogEntry) *decisionsUI {
	ui := &decisionsUI{}

	ui.app = tview.NewApplication()
	ui.tabs = tview.NewPages()

	mkBrowserPanel(ui, entries)
	mkCheckDetailsPanel(ui)
	mkPlanDetailsPanel(ui)

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

//nolint:mnd
func mkBrowserPanel(ui *decisionsUI, entries []*auditv1.DecisionLogEntry) {
	ui.browser = &browserPanel{
		entriesTable: tview.NewTable().
			SetFixed(1, 0).
			SetBorders(false).
			SetSeparator(tview.Borders.Vertical).
			SetSelectable(true, false),
		jsonView: tview.NewTextView().SetDynamicColors(true),
	}

	ui.browser.focusOrder = []tview.Primitive{
		ui.browser.entriesTable,
		ui.browser.jsonView,
	}

	ui.browser.entriesTable.SetBorder(true).SetTitle("| Decisions |")
	ui.browser.jsonView.SetBorder(true).SetTitle("| Data |")

	populateEntriesTable(ui, entries)

	info := tview.NewTextView().SetDynamicColors(true).SetWrap(false)
	fmt.Fprintf(info, "%s  %s  %s", keyDesc("⭾", "Switch between panes"), keyDesc("⏎", "View details"), keyDesc("Q", "Exit"))

	layout := tview.NewGrid().
		SetColumns(-1, -1).
		SetRows(0, 1).
		SetBorders(false).
		AddItem(ui.browser.entriesTable, 0, 0, 1, 1, 0, 0, true).
		AddItem(ui.browser.jsonView, 0, 1, 1, 1, 0, 0, false).
		AddItem(info, 1, 0, 1, 2, 1, 1, false)

	layout.SetInputCapture(func(key *tcell.EventKey) *tcell.EventKey {
		switch key.Key() {
		case tcell.KeyTab:
			ui.app.SetFocus(ui.browser.switchFocus(false))
			return nil
		case tcell.KeyBacktab:
			ui.app.SetFocus(ui.browser.switchFocus(true))
			return nil
		case tcell.KeyEsc:
			ui.app.Stop()
			return nil
		case tcell.KeyEnter:
			if ui.browser.jsonView.HasFocus() {
				row, col := ui.browser.entriesTable.GetSelection()
				ui.entrySelectedFunc(row, col)
				return nil
			}
			return key
		default:
			return key
		}
	})

	ui.tabs.AddPage(browserKey, layout, true, true)
}

//nolint:mnd
func populateEntriesTable(ui *decisionsUI, entries []*auditv1.DecisionLogEntry) {
	ui.browser.entriesTable.SetCell(0, 0, tview.NewTableCell("Call ID").SetAlign(tview.AlignCenter).SetAttributes(tcell.AttrBold))
	ui.browser.entriesTable.SetCell(0, 1, tview.NewTableCell("Timestamp").SetAlign(tview.AlignCenter).SetAttributes(tcell.AttrBold))
	ui.browser.entriesTable.SetCell(0, 2, tview.NewTableCell("Request ID").SetAlign(tview.AlignCenter).SetAttributes(tcell.AttrBold))
	ui.browser.entriesTable.SetCell(0, 3, tview.NewTableCell("Address").SetAlign(tview.AlignCenter).SetAttributes(tcell.AttrBold))
	ui.browser.entriesTable.SetCell(0, 4, tview.NewTableCell("User Agent").SetAlign(tview.AlignCenter).SetAttributes(tcell.AttrBold))
	ui.browser.entriesTable.SetCell(0, 5, tview.NewTableCell("Forwarded For").SetAlign(tview.AlignCenter).SetAttributes(tcell.AttrBold))

	rowIndex := 1
	for _, entry := range entries {
		ui.browser.entriesTable.SetCell(rowIndex, 0, tview.NewTableCell(entry.CallId).SetReference(entry))
		ui.browser.entriesTable.SetCell(rowIndex, 1, tview.NewTableCell(entry.Timestamp.AsTime().Format(time.RFC3339)))

		requestID := "-"
		switch t := entry.Method.(type) {
		case *auditv1.DecisionLogEntry_CheckResources_:
			if len(t.CheckResources.Inputs) > 0 {
				requestID = t.CheckResources.Inputs[0].RequestId
			}
		case *auditv1.DecisionLogEntry_PlanResources_:
			requestID = t.PlanResources.Input.RequestId
		}

		ui.browser.entriesTable.SetCell(rowIndex, 2, tview.NewTableCell(requestID))
		ui.browser.entriesTable.SetCell(rowIndex, 3, tview.NewTableCell(entry.Peer.Address))
		ui.browser.entriesTable.SetCell(rowIndex, 4, tview.NewTableCell(entry.Peer.UserAgent))
		ui.browser.entriesTable.SetCell(rowIndex, 5, tview.NewTableCell(entry.Peer.ForwardedFor))
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

	ui.browser.entriesTable.SetSelectedFunc(ui.entrySelectedFunc)
}

//nolint:mnd
func mkCheckDetailsPanel(ui *decisionsUI) {
	ui.checkDetails = &checkDetailsPanel{
		inputsList:    tview.NewList(),
		principalView: tview.NewTextView().SetDynamicColors(true),
		resourceView:  tview.NewTextView().SetDynamicColors(true),
		actionsTable:  tview.NewTable().SetFixed(1, 0).SetBorders(true),
		derivedRolesView: tview.NewTextView().
			SetDynamicColors(true).
			SetWrap(false).
			SetTextAlign(tview.AlignCenter).
			SetTextColor(tcell.ColorSeaGreen),
	}

	ui.checkDetails.focusOrder = []tview.Primitive{
		ui.checkDetails.inputsList,
		ui.checkDetails.principalView,
		ui.checkDetails.resourceView,
		ui.checkDetails.actionsTable,
	}

	ui.checkDetails.inputsList.SetBorder(true).SetTitle(fmt.Sprintf("| %stems |", keyCode("I")))
	ui.checkDetails.actionsTable.SetBorder(true).SetTitle(fmt.Sprintf("| %sctions |", keyCode("A")))
	ui.checkDetails.principalView.SetBorder(true).SetTitle(fmt.Sprintf("| %srincipal |", keyCode("P")))
	ui.checkDetails.resourceView.SetBorder(true).SetTitle(fmt.Sprintf("| %sesource |", keyCode("R")))
	ui.checkDetails.derivedRolesView.SetBorder(true).SetTitle("| Effective Derived Roles |")

	info := tview.NewTextView().SetDynamicColors(true).SetWrap(false)
	fmt.Fprintf(info, "%s  %s  %s", keyDesc("⭾", "Switch between panes"), keyDesc("ESC", "Back"), keyDesc("Q", "Exit"))

	layout := tview.NewFlex().
		SetDirection(tview.FlexRow).
		AddItem(tview.NewFlex().
			AddItem(ui.checkDetails.inputsList, 0, 1, true).
			AddItem(tview.NewFlex().
				SetDirection(tview.FlexRow).
				AddItem(tview.NewFlex().
					AddItem(ui.checkDetails.principalView, 0, 1, true).
					AddItem(ui.checkDetails.resourceView, 0, 1, false), 0, 2, true).
				AddItem(ui.checkDetails.actionsTable, 0, 1, false).
				AddItem(ui.checkDetails.derivedRolesView, 3, 0, false), 0, 4, false), 0, 1, true).
		AddItem(info, 1, 0, false)

	layout.SetInputCapture(func(key *tcell.EventKey) *tcell.EventKey {
		switch key.Key() {
		case tcell.KeyTab:
			ui.app.SetFocus(ui.checkDetails.switchFocus(false))
			return nil
		case tcell.KeyBacktab:
			ui.app.SetFocus(ui.checkDetails.switchFocus(true))
			return nil
		case tcell.KeyEsc:
			ui.tabs.SwitchToPage(browserKey)
			return nil
		case tcell.KeyRune:
			switch key.Rune() {
			case 'p', 'P':
				ui.app.SetFocus(ui.checkDetails.principalView)
				return nil
			case 'r', 'R':
				ui.app.SetFocus(ui.checkDetails.resourceView)
				return nil
			case 'a', 'A':
				ui.app.SetFocus(ui.checkDetails.actionsTable)
				return nil
			case 'i', 'I':
				ui.app.SetFocus(ui.checkDetails.inputsList)
				return nil
			default:
				return key
			}
		default:
			return key
		}
	})

	ui.tabs.AddPage(checkDetailsKey, layout, true, false)
}

//nolint:mnd
func mkPlanDetailsPanel(ui *decisionsUI) {
	ui.planDetails = &planDetailsPanel{
		principalView: tview.NewTextView().SetDynamicColors(true),
		resourceView:  tview.NewTextView().SetDynamicColors(true),
		planView:      tview.NewTextView().SetDynamicColors(true),
		debugView:     tview.NewTextView().SetTextAlign(tview.AlignCenter).SetTextColor(tcell.ColorGreen),
	}

	ui.planDetails.focusOrder = []tview.Primitive{
		ui.planDetails.principalView,
		ui.planDetails.resourceView,
		ui.planDetails.planView,
	}

	ui.planDetails.principalView.SetBorder(true).SetTitle(fmt.Sprintf("| %srincipal |", keyCode("P")))
	ui.planDetails.resourceView.SetBorder(true).SetTitle(fmt.Sprintf("| %sesource |", keyCode("R")))
	ui.planDetails.planView.SetBorder(true).SetTitle(fmt.Sprintf("| P%san |", keyCode("l")))
	ui.planDetails.debugView.SetBorder(true).SetTitle("| Expression |")

	info := tview.NewTextView().SetDynamicColors(true).SetWrap(false)
	fmt.Fprintf(info, "%s  %s  %s", keyDesc("⭾", "Switch between panes"), keyDesc("ESC", "Back"), keyDesc("Q", "Exit"))

	layout := tview.NewFlex().
		SetDirection(tview.FlexRow).
		AddItem(tview.NewFlex().
			AddItem(ui.planDetails.principalView, 0, 1, false).
			AddItem(ui.planDetails.resourceView, 0, 1, false), 0, 2, false).
		AddItem(ui.planDetails.planView, 0, 4, true).
		AddItem(ui.planDetails.debugView, 3, 0, false).
		AddItem(info, 1, 0, false)

	layout.SetInputCapture(func(key *tcell.EventKey) *tcell.EventKey {
		switch key.Key() {
		case tcell.KeyTab:
			ui.app.SetFocus(ui.planDetails.switchFocus(false))
			return nil
		case tcell.KeyBacktab:
			ui.app.SetFocus(ui.planDetails.switchFocus(true))
			return nil
		case tcell.KeyEsc:
			ui.tabs.SwitchToPage(browserKey)
			return nil
		case tcell.KeyRune:
			switch key.Rune() {
			case 'p', 'P':
				ui.app.SetFocus(ui.planDetails.principalView)
				return nil
			case 'r', 'R':
				ui.app.SetFocus(ui.planDetails.resourceView)
				return nil
			case 'l', 'L':
				ui.app.SetFocus(ui.planDetails.planView)
				return nil
			default:
				return key
			}
		default:
			return key
		}
	})

	ui.tabs.AddPage(planDetailsKey, layout, true, false)
}

func (d *decisionsUI) Start() error {
	return d.app.Run()
}

func (d *decisionsUI) entrySelectedFunc(row, _ int) {
	col := d.browser.entriesTable.GetCell(row, 0)
	entryRef := col.GetReference()

	if entry, ok := entryRef.(*auditv1.DecisionLogEntry); ok {
		d.showDetailsPanel(entry)
	}
}

func (d *decisionsUI) showDetailsPanel(entry *auditv1.DecisionLogEntry) {
	switch t := entry.Method.(type) {
	case *auditv1.DecisionLogEntry_CheckResources_:
		d.showCheckDetailsPanel(t.CheckResources)
	case *auditv1.DecisionLogEntry_PlanResources_:
		d.showPlanDetailsPanel(t.PlanResources)
	}
}

//nolint:mnd
func (d *decisionsUI) showCheckDetailsPanel(entry *auditv1.DecisionLogEntry_CheckResources) {
	d.checkDetails.inputsList.Clear()

	printer := newPrettyJSON()
	for i, inp := range entry.Inputs {
		text := fmt.Sprintf("%d. %s|%s|%s", i+1, inp.Principal.Id, inp.Resource.Kind, inp.Resource.Id)
		d.checkDetails.inputsList.AddItem(text, "", 0, nil)
	}

	changedFunc := func(index int, _, _ string, _ rune) {
		inp := entry.Inputs[index]

		d.checkDetails.principalView.Clear()
		printer.write(tview.ANSIWriter(d.checkDetails.principalView), inp.Principal)

		d.checkDetails.resourceView.Clear()
		printer.write(tview.ANSIWriter(d.checkDetails.resourceView), inp.Resource)

		output := entry.Outputs[index]
		d.checkDetails.actionsTable.Clear()

		d.checkDetails.actionsTable.SetCell(0, 0, tview.NewTableCell(""))
		d.checkDetails.actionsTable.SetCell(0, 1, tview.NewTableCell("Action").
			SetAttributes(tcell.AttrBold).
			SetAlign(tview.AlignCenter).
			SetExpansion(2))
		d.checkDetails.actionsTable.SetCell(0, 2, tview.NewTableCell("Effect").
			SetAttributes(tcell.AttrBold).
			SetAlign(tview.AlignCenter).
			SetExpansion(1))
		d.checkDetails.actionsTable.SetCell(0, 3, tview.NewTableCell("Policy").
			SetAttributes(tcell.AttrBold).
			SetAlign(tview.AlignCenter).
			SetExpansion(4))

		row := 1
		for action, actionMeta := range output.Actions {
			icon := "  ✖  "
			fgColour := tcell.ColorRed
			if actionMeta.Effect == effectv1.Effect_EFFECT_ALLOW {
				icon = "  ✔  "
				fgColour = tcell.ColorGreen
			}

			d.checkDetails.actionsTable.SetCell(row, 0, tview.NewTableCell(icon).
				SetAlign(tview.AlignCenter).
				SetAttributes(tcell.AttrBold).
				SetTextColor(fgColour))
			d.checkDetails.actionsTable.SetCell(row, 1, tview.NewTableCell(action))
			d.checkDetails.actionsTable.SetCell(row, 2, tview.NewTableCell(actionMeta.Effect.String()))
			d.checkDetails.actionsTable.SetCell(row, 3, tview.NewTableCell(actionMeta.Policy))
			row++
		}

		d.checkDetails.derivedRolesView.Clear()
		fmt.Fprint(d.checkDetails.derivedRolesView, strings.Join(output.EffectiveDerivedRoles, ","))
	}

	d.checkDetails.inputsList.SetChangedFunc(changedFunc)
	changedFunc(0, "", "", 0)

	d.tabs.SwitchToPage(checkDetailsKey)
}

func (d *decisionsUI) showPlanDetailsPanel(entry *auditv1.DecisionLogEntry_PlanResources) {
	printer := newPrettyJSON()
	inp := entry.Input

	d.planDetails.principalView.Clear()
	printer.write(tview.ANSIWriter(d.planDetails.principalView), inp.Principal)

	d.planDetails.resourceView.Clear()
	printer.write(tview.ANSIWriter(d.planDetails.resourceView), inp.Resource)

	d.planDetails.planView.Clear()
	d.planDetails.debugView.Clear()
	if entry.Error != "" {
		fmt.Fprintln(d.planDetails.planView, entry.Error)
	} else {
		if entry.Output.FilterDebug != "" {
			fmt.Fprint(d.planDetails.debugView, entry.Output.FilterDebug)
		}
		printer.write(tview.ANSIWriter(d.planDetails.planView), entry.Output.Filter)
	}

	d.tabs.SwitchToPage(planDetailsKey)
}

func (bp *browserPanel) switchFocus(backward bool) tview.Primitive {
	return switchFocus(bp.focusOrder, backward)
}

func (cdp *checkDetailsPanel) switchFocus(backward bool) tview.Primitive {
	return switchFocus(cdp.focusOrder, backward)
}

func (pdp *planDetailsPanel) switchFocus(backward bool) tview.Primitive {
	return switchFocus(pdp.focusOrder, backward)
}

func switchFocus(items []tview.Primitive, backward bool) tview.Primitive {
	for i, p := range items {
		if !p.HasFocus() {
			continue
		}

		if backward {
			i--
		} else {
			i++
		}

		idx := i % len(items)
		if idx < 0 {
			return items[len(items)+idx]
		}

		return items[idx]
	}

	return items[0]
}

func keyCode(key string) string {
	return fmt.Sprintf("[darkcyan::b]%s[-:-:-]", key)
}

func keyDesc(key, desc string) string {
	return fmt.Sprintf("%s %s", keyCode(key), desc)
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
		style:     styles.Get("monokai"),
	}
}

func (p *prettyJSON) write(out io.Writer, msg proto.Message) {
	w := bufio.NewWriter(out)
	defer w.Flush()

	iterator, err := p.lexer.Tokenise(nil, protojson.Format(msg))
	if err != nil {
		_, _ = w.WriteString(fmt.Sprintf("Error tokenising JSON: %v", err))
		return
	}

	if err := p.formatter.Format(w, p.style, iterator); err != nil {
		_, _ = w.WriteString(fmt.Sprintf("Error printing JSON: %v", err))
	}
}
