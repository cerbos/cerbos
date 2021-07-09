// Copyright 2021 Zenauth Ltd.

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

	requestv1 "github.com/cerbos/cerbos/internal/genpb/request/v1"
	responsev1 "github.com/cerbos/cerbos/internal/genpb/response/v1"
	svcv1 "github.com/cerbos/cerbos/internal/genpb/svc/v1"
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

type clientGenFunc func() (svcv1.CerbosAdminServiceClient, error)

func NewAuditCmd(clientGen clientGenFunc) *cobra.Command {
	cmd := &cobra.Command{
		Use:     "audit",
		Short:   "View audit logs",
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
