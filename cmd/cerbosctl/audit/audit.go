// Copyright 2021 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/alecthomas/chroma"
	"github.com/alecthomas/chroma/formatters"
	"github.com/alecthomas/chroma/lexers"
	"github.com/alecthomas/chroma/styles"
	"github.com/jwalton/gchalk"
	"github.com/spf13/cobra"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"

	auditv1 "github.com/cerbos/cerbos/api/genpb/cerbos/audit/v1"
	requestv1 "github.com/cerbos/cerbos/api/genpb/cerbos/request/v1"
	"github.com/cerbos/cerbos/client"
)

const dashLen = 54

var (
	auditFlags struct {
		kind kindFlag
		raw  bool
	}

	auditFilterFlags = NewFilterDef()
	newline          = []byte("\n")
)

var longDesc = `View audit logs.
Requires audit logging to be enabled on the server. Supports several ways of filtering the data.

tail: View the last N records
between: View records captured between two timestamps. The timestamps must be formatted as ISO-8601
since: View records from X hours/minutes/seconds ago to now. Unit suffixes are: h=hours, m=minutes s=seconds
lookup: View a specific record using the Cerbos Call ID`

var exampleDesc = `
# View the last 10 access logs 
cerbos ctl audit --kind=access --tail=10

# View the decision logs from midnight 2021-07-01 to midnight 2021-07-02
cerbos ctl audit --kind=decision --between=2021-07-01T00:00:00Z,2021-07-02T00:00:00Z

# View the decision logs from midnight 2021-07-01 to now
cerbos ctl audit --kind=decision --between=2021-07-01T00:00:00Z

# View the access logs from 3 hours ago to now as newline-delimited JSON
cerbos ctl audit --kind=access --since=3h --raw

# View a specific access log entry by call ID
cerbos ctl audit --kind=access --lookup=01F9Y5MFYTX7Y87A30CTJ2FB0S
`

type withClient func(fn func(c client.AdminClient, cmd *cobra.Command, args []string) error) func(cmd *cobra.Command, args []string) error

func NewAuditCmd(fn withClient) *cobra.Command {
	cmd := &cobra.Command{
		Use:     "audit",
		Short:   "View audit logs",
		Long:    longDesc,
		Example: exampleDesc,
		PreRunE: checkAuditFlags,
		RunE:    fn(runAuditCmdF),
	}

	cmd.Flags().Var(&auditFlags.kind, "kind", "Kind of log entry ('access' or 'decision')")
	cmd.Flags().BoolVar(&auditFlags.raw, "raw", false, "Output results without formatting or colours")
	cmd.Flags().AddFlagSet(auditFilterFlags.FlagSet())

	return cmd
}

func checkAuditFlags(_ *cobra.Command, _ []string) error {
	return auditFilterFlags.Validate()
}

func runAuditCmdF(c client.AdminClient, cmd *cobra.Command, _ []string) error {
	var writer auditLogWriter
	if auditFlags.raw {
		writer = newRawAuditLogWriter(cmd.OutOrStdout())
	} else {
		writer = newRichAuditLogWriter(cmd.OutOrStdout())
	}
	defer writer.flush()

	switch kind := auditFlags.kind.Kind(); kind {
	case requestv1.ListAuditLogEntriesRequest_KIND_DECISION, requestv1.ListAuditLogEntriesRequest_KIND_UNSPECIFIED:
		decisionLogs, err := c.DecisionLogs(context.Background(), genAuditLogOptions(auditFilterFlags))
		if err != nil {
			return fmt.Errorf("could not get decision logs: %w", err)
		}

		if err = streamDecisionLogsToWriter(writer, decisionLogs); err != nil {
			return fmt.Errorf("could not write decision logs: %w", err)
		}
	case requestv1.ListAuditLogEntriesRequest_KIND_ACCESS:
		accessLogs, err := c.AccessLogs(context.Background(), genAuditLogOptions(auditFilterFlags))
		if err != nil {
			return fmt.Errorf("could not get access logs: %w", err)
		}

		if err = streamAccessLogsToWriter(writer, accessLogs); err != nil {
			return fmt.Errorf("could not write access logs: %w", err)
		}
	}

	return nil
}

func genAuditLogOptions(filter *FilterDef) client.AuditLogOptions {
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

func streamAccessLogsToWriter(writer auditLogWriter, entries <-chan *client.AccessLogEntry) error {
	for e := range entries {
		if err := e.Err; err != nil {
			return fmt.Errorf("error while receiving access logs: %w", err)
		}
		if err := writer.write(e.Log); err != nil {
			return err
		}
	}

	return nil
}

func streamDecisionLogsToWriter(writer auditLogWriter, entries <-chan *client.DecisionLogEntry) error {
	for e := range entries {
		if err := e.Err; err != nil {
			return fmt.Errorf("error while receiving decision logs: %w", err)
		}
		if err := writer.write(e.Log); err != nil {
			return err
		}
	}

	return nil
}

type auditLogWriter interface {
	write(proto.Message) error
	flush()
}

func newRawAuditLogWriter(out io.Writer) *rawAuditLogWriter {
	return &rawAuditLogWriter{out: out}
}

type rawAuditLogWriter struct {
	out io.Writer
}

func (r *rawAuditLogWriter) write(entry proto.Message) error {
	if entry == nil {
		return nil
	}

	outBytes, err := protojson.Marshal(entry)
	if err != nil {
		return err
	}

	if _, err := r.out.Write(outBytes); err != nil {
		return err
	}

	_, err = r.out.Write(newline)
	return err
}

func (r *rawAuditLogWriter) flush() {}

type richAuditLogWriter struct {
	out       *bufio.Writer
	lexer     chroma.Lexer
	formatter chroma.Formatter
	rowStyle  func(...string) string
}

func newRichAuditLogWriter(out io.Writer) *richAuditLogWriter {
	lexer := lexers.Get("json")
	if lexer == nil {
		lexer = lexers.Fallback
	}

	var formatter chroma.Formatter
	switch gchalk.GetLevel() {
	case gchalk.LevelAnsi256:
		formatter = formatters.TTY256
	case gchalk.LevelAnsi16m:
		formatter = formatters.TTY16m
	default:
		formatter = formatters.TTY
	}

	return &richAuditLogWriter{
		out:       bufio.NewWriter(out),
		lexer:     chroma.Coalesce(lexer),
		formatter: formatter,
		rowStyle:  gchalk.WithHex("#eeeeee").WithBgHex("#005fff").Bold,
	}
}

func (r *richAuditLogWriter) write(entry proto.Message) error {
	switch e := entry.(type) {
	case *auditv1.AccessLogEntry:
		r.header(fmt.Sprintf("%s %s", e.CallId, strings.Repeat("┈", dashLen)))
		return r.formattedJSON(e)
	case *auditv1.DecisionLogEntry:
		r.header(fmt.Sprintf("%s %s", e.CallId, strings.Repeat("┈", dashLen)))
		return r.formattedJSON(e)
	default:
		return nil
	}
}

func (r *richAuditLogWriter) header(h string) {
	_, _ = r.out.WriteString("\n\n")
	_, _ = r.out.WriteString(r.rowStyle(h))
	_, _ = r.out.WriteString("\n")
}

func (r *richAuditLogWriter) formattedJSON(msg proto.Message) error {
	iterator, err := r.lexer.Tokenise(nil, protojson.Format(msg))
	if err != nil {
		return err
	}

	if err := r.formatter.Format(r.out, styles.SolarizedDark256, iterator); err != nil {
		return err
	}

	_, err = r.out.Write(newline)
	return err
}

func (r *richAuditLogWriter) flush() {
	_ = r.out.Flush()
}
