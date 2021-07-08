// Copyright 2021 Zenauth Ltd.

package ctl

import (
	"bufio"
	"context"
	"encoding/csv"
	"errors"
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
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/timestamppb"

	requestv1 "github.com/cerbos/cerbos/internal/genpb/request/v1"
	responsev1 "github.com/cerbos/cerbos/internal/genpb/response/v1"
)

const dashLen = 54

var (
	errMoreThanOneFilter = errors.New("more than one filter specified: choose from either `tail`, `between`, `since` or `lookup`")
	errNoFilter          = errors.New("unknown filter")
	newline              = []byte("\n")
)

var auditFlags struct {
	kind    kindFlag
	tail    uint16
	between timerangeFlag
	since   time.Duration
	lookup  string
	raw     bool
}

func newAuditCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "audit",
		Short:   "View audit logs",
		PreRunE: checkAuditFlags,
		RunE:    runAuditCmd,
	}

	cmd.Flags().Var(&auditFlags.kind, "kind", "Kind of log entry ('access' or 'decision')")
	cmd.Flags().Uint16Var(&auditFlags.tail, "tail", 0, "View last N entries")
	cmd.Flags().Var(&auditFlags.between, "between", "View entries between two timestamps")
	cmd.Flags().DurationVar(&auditFlags.since, "since", 0, "View entries from last N hours/minutes")
	cmd.Flags().StringVar(&auditFlags.lookup, "lookup", "", "View by call ID")
	cmd.Flags().BoolVar(&auditFlags.raw, "raw", false, "Output results without formatting or colours")

	return cmd
}

func checkAuditFlags(_ *cobra.Command, _ []string) error {
	filterCount := 0
	if auditFlags.tail > 0 {
		filterCount++
	}

	if auditFlags.between.isSet() {
		filterCount++
	}

	if auditFlags.since > 0 {
		filterCount++
	}

	if auditFlags.lookup != "" {
		filterCount++
	}

	if filterCount > 1 {
		return errMoreThanOneFilter
	}

	if auditFlags.kind.Kind() == requestv1.ListAuditLogEntriesRequest_KIND_UNSPECIFIED {
		auditFlags.kind = kindFlag(requestv1.ListAuditLogEntriesRequest_KIND_DECISION)
	}

	if filterCount == 0 {
		auditFlags.tail = 25
	}

	return nil
}

func runAuditCmd(cmd *cobra.Command, _ []string) error {
	client, err := createAdminClient()
	if err != nil {
		return err
	}

	req := &requestv1.ListAuditLogEntriesRequest{
		Kind: auditFlags.kind.Kind(),
	}

	switch {
	case auditFlags.tail > 0:
		req.Filter = &requestv1.ListAuditLogEntriesRequest_Tail{Tail: uint32(auditFlags.tail)}
	case auditFlags.between.isSet():
		req.Filter = &requestv1.ListAuditLogEntriesRequest_Between{
			Between: &requestv1.ListAuditLogEntriesRequest_TimeRange{
				Start: auditFlags.between.tsVals[0],
				End:   auditFlags.between.tsVals[1],
			},
		}
	case auditFlags.since > 0:
		req.Filter = &requestv1.ListAuditLogEntriesRequest_Since{Since: durationpb.New(auditFlags.since)}
	case auditFlags.lookup != "":
		req.Filter = &requestv1.ListAuditLogEntriesRequest_Lookup{Lookup: auditFlags.lookup}
	default:
		return errNoFilter
	}

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

type kindFlag requestv1.ListAuditLogEntriesRequest_Kind

func (kf kindFlag) Kind() requestv1.ListAuditLogEntriesRequest_Kind {
	return requestv1.ListAuditLogEntriesRequest_Kind(kf)
}

func (kf kindFlag) String() string {
	return "decision"
}

func (kf *kindFlag) Set(v string) error {
	switch strings.ToLower(v) {
	case "access":
		*kf = kindFlag(requestv1.ListAuditLogEntriesRequest_KIND_ACCESS)
		return nil
	case "decision":
		*kf = kindFlag(requestv1.ListAuditLogEntriesRequest_KIND_DECISION)
		return nil
	default:
		return fmt.Errorf("unknown kind [%s]: valid values are 'access' or 'decision'", v)
	}
}

func (kf kindFlag) Type() string {
	return "kindFlag"
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
