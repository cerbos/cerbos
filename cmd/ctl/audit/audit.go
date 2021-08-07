// Copyright 2021 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/alecthomas/chroma"
	"github.com/alecthomas/chroma/formatters"
	"github.com/alecthomas/chroma/lexers"
	"github.com/alecthomas/chroma/styles"
	"github.com/jwalton/gchalk"
	"github.com/spf13/cobra"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"

	requestv1 "github.com/cerbos/cerbos/api/genpb/cerbos/request/v1"
	responsev1 "github.com/cerbos/cerbos/api/genpb/cerbos/response/v1"
	svcv1 "github.com/cerbos/cerbos/api/genpb/cerbos/svc/v1"
	"github.com/cerbos/cerbos/internal/util"
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

type clientGenFunc func() (svcv1.CerbosAdminServiceClient, error)

func NewAuditCmd(clientGen clientGenFunc) *cobra.Command {
	cmd := &cobra.Command{
		Use:     "audit",
		Short:   "View audit logs",
		Long:    longDesc,
		Example: exampleDesc,
		PreRunE: checkAuditFlags,
		RunE:    runAuditCmd(clientGen),
	}

	cmd.Flags().Var(&auditFlags.kind, "kind", "Kind of log entry ('access' or 'decision')")
	cmd.Flags().BoolVar(&auditFlags.raw, "raw", false, "Output results without formatting or colours")
	cmd.Flags().AddFlagSet(auditFilterFlags.FlagSet())

	return cmd
}

func checkAuditFlags(_ *cobra.Command, _ []string) error {
	if err := auditFilterFlags.Validate(); err != nil {
		return err
	}

	if auditFlags.kind.Kind() == requestv1.ListAuditLogEntriesRequest_KIND_UNSPECIFIED {
		auditFlags.kind = kindFlag(requestv1.ListAuditLogEntriesRequest_KIND_DECISION)
	}

	return nil
}

func runAuditCmd(clientGen clientGenFunc) func(*cobra.Command, []string) error {
	return func(cmd *cobra.Command, _ []string) error {
		client, err := clientGen()
		if err != nil {
			return err
		}

		r, err := client.ServerStatus(context.Background(), &requestv1.ServerStatusRequest{})
		if err != nil {
			return err
		}

		if r.Version != util.Version {
			return fmt.Errorf("server version and client version does not match: server: %s, client: %s", r.Version, util.Version)
		}

		req := auditFilterFlags.BuildRequest(auditFlags.kind.Kind())
		resp, err := client.ListAuditLogEntries(context.Background(), req)
		if err != nil {
			return err
		}

		out := cmd.OutOrStdout()

		var writer auditLogWriter
		if auditFlags.raw {
			writer = newRawAuditLogWriter(out)
		} else {
			writer = newRichAuditLogWriter(out)
		}

		defer writer.flush()

		for {
			entry, err := resp.Recv()
			if err != nil {
				if errors.Is(err, io.EOF) {
					return nil
				}

				return err
			}

			if err := writer.write(entry); err != nil {
				return err
			}
		}
	}
}

type auditLogWriter interface {
	write(*responsev1.ListAuditLogEntriesResponse) error
	flush()
}

func newRawAuditLogWriter(out io.Writer) *rawAuditLogWriter {
	return &rawAuditLogWriter{out: out}
}

type rawAuditLogWriter struct {
	out io.Writer
}

func (r *rawAuditLogWriter) write(entry *responsev1.ListAuditLogEntriesResponse) error {
	e := extractEntry(entry)
	if e == nil {
		return nil
	}

	outBytes, err := protojson.Marshal(e)
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

func (r *richAuditLogWriter) write(entry *responsev1.ListAuditLogEntriesResponse) error {
	switch e := entry.Entry.(type) {
	case *responsev1.ListAuditLogEntriesResponse_AccessLogEntry:
		r.header(fmt.Sprintf("%s %s", e.AccessLogEntry.CallId, strings.Repeat("┈", dashLen)))
		return r.formattedJSON(e.AccessLogEntry)
	case *responsev1.ListAuditLogEntriesResponse_DecisionLogEntry:
		r.header(fmt.Sprintf("%s %s", e.DecisionLogEntry.CallId, strings.Repeat("┈", dashLen)))
		return r.formattedJSON(e.DecisionLogEntry)
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

func extractEntry(entry *responsev1.ListAuditLogEntriesResponse) proto.Message {
	switch e := entry.Entry.(type) {
	case *responsev1.ListAuditLogEntriesResponse_AccessLogEntry:
		return e.AccessLogEntry
	case *responsev1.ListAuditLogEntriesResponse_DecisionLogEntry:
		return e.DecisionLogEntry
	default:
		return nil
	}
}
