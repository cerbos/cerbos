// Copyright 2021-2025 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package outputcolor_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/alecthomas/kong"
	"github.com/cerbos/cerbos/internal/outputcolor"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLevelEnabled(t *testing.T) {
	assert.False(t, outputcolor.None.Enabled(), "None")
	assert.True(t, outputcolor.Basic.Enabled(), "Basic")
	assert.True(t, outputcolor.Ansi256.Enabled(), "Ansi256")
	assert.True(t, outputcolor.Ansi16m.Enabled(), "Ansi16m")
}

func TestTypeMapper(t *testing.T) {
	tests := []struct {
		args          []string
		wantLevel     outputcolor.Level
		wantLeftovers []string
		wantNil       bool
		wantErr       string
	}{
		{
			args:    []string{},
			wantNil: true,
		},
		{
			args:    []string{"-cauto"},
			wantNil: true,
		},
		{
			args:    []string{"-c", "auto"},
			wantNil: true,
		},
		{
			args:    []string{"--color=auto"},
			wantNil: true,
		},
		{
			args:    []string{"--color", "auto"},
			wantNil: true,
		},
		{
			args:      []string{"-cfalse"},
			wantLevel: outputcolor.None,
		},
		{
			args:      []string{"-c", "false"},
			wantLevel: outputcolor.None,
		},
		{
			args:      []string{"--color=false"},
			wantLevel: outputcolor.None,
		},
		{
			args:      []string{"--color", "false"},
			wantLevel: outputcolor.None,
		},
		{
			args:      []string{"-cnever"},
			wantLevel: outputcolor.None,
		},
		{
			args:      []string{"-c", "never"},
			wantLevel: outputcolor.None,
		},
		{
			args:      []string{"--color=never"},
			wantLevel: outputcolor.None,
		},
		{
			args:      []string{"--color", "never"},
			wantLevel: outputcolor.None,
		},
		{
			args:      []string{"-c"},
			wantLevel: outputcolor.Basic,
		},
		{
			args:      []string{"--color"},
			wantLevel: outputcolor.Basic,
		},
		{
			args:      []string{"-ctrue"},
			wantLevel: outputcolor.Basic,
		},
		{
			args:      []string{"-c", "true"},
			wantLevel: outputcolor.Basic,
		},
		{
			args:      []string{"--color=true"},
			wantLevel: outputcolor.Basic,
		},
		{
			args:      []string{"--color", "true"},
			wantLevel: outputcolor.Basic,
		},
		{
			args:      []string{"-calways"},
			wantLevel: outputcolor.Basic,
		},
		{
			args:      []string{"-c", "always"},
			wantLevel: outputcolor.Basic,
		},
		{
			args:      []string{"--color=always"},
			wantLevel: outputcolor.Basic,
		},
		{
			args:      []string{"--color", "always"},
			wantLevel: outputcolor.Basic,
		},
		{
			args:      []string{"-c256"},
			wantLevel: outputcolor.Ansi256,
		},
		{
			args:      []string{"-c", "256"},
			wantLevel: outputcolor.Ansi256,
		},
		{
			args:      []string{"--color=256"},
			wantLevel: outputcolor.Ansi256,
		},
		{
			args:      []string{"--color", "256"},
			wantLevel: outputcolor.Ansi256,
		},
		{
			args:      []string{"-c16m"},
			wantLevel: outputcolor.Ansi16m,
		},
		{
			args:      []string{"-c", "16m"},
			wantLevel: outputcolor.Ansi16m,
		},
		{
			args:      []string{"--color=16m"},
			wantLevel: outputcolor.Ansi16m,
		},
		{
			args:      []string{"--color", "16m"},
			wantLevel: outputcolor.Ansi16m,
		},
		{
			args:      []string{"-cfull"},
			wantLevel: outputcolor.Ansi16m,
		},
		{
			args:      []string{"-c", "full"},
			wantLevel: outputcolor.Ansi16m,
		},
		{
			args:      []string{"--color=full"},
			wantLevel: outputcolor.Ansi16m,
		},
		{
			args:      []string{"--color", "full"},
			wantLevel: outputcolor.Ansi16m,
		},
		{
			args:      []string{"-ctruecolor"},
			wantLevel: outputcolor.Ansi16m,
		},
		{
			args:      []string{"-c", "truecolor"},
			wantLevel: outputcolor.Ansi16m,
		},
		{
			args:      []string{"--color=truecolor"},
			wantLevel: outputcolor.Ansi16m,
		},
		{
			args:      []string{"--color", "truecolor"},
			wantLevel: outputcolor.Ansi16m,
		},
		{
			args:    []string{"-cfoo"},
			wantErr: "unknown flag -f",
		},
		{
			args:          []string{"-c", "foo"},
			wantLevel:     outputcolor.Basic,
			wantLeftovers: []string{"foo"},
		},
		{
			args:    []string{"--color=foo"},
			wantErr: `invalid value for output color level: "foo"`,
		},
		{
			args:          []string{"--color", "foo"},
			wantLevel:     outputcolor.Basic,
			wantLeftovers: []string{"foo"},
		},
	}

	for _, tt := range tests {
		t.Run(strings.Join(tt.args, " "), func(t *testing.T) {
			level, leftovers, err := parse(t, tt.args)

			if tt.wantErr != "" {
				require.Error(t, err, tt.wantErr)
				require.Contains(t, err.Error(), tt.wantErr)
				return
			}

			require.NoError(t, err)

			if tt.wantNil {
				assert.Nil(t, level)
			} else if assert.NotNil(t, level) {
				assert.Equal(t, tt.wantLevel, *level)
			}

			assert.Equal(t, tt.wantLeftovers, leftovers)
		})
	}
}

func parse(t *testing.T, args []string) (*outputcolor.Level, []string, error) {
	t.Helper()

	var cli struct {
		Color     *outputcolor.Level `short:"c"`
		Leftovers []string           `arg:"" optional:""`
	}

	parser, err := kong.New(&cli, outputcolor.TypeMapper)
	require.NoError(t, err, "failed to create command-line argument parser")

	var parseError *kong.ParseError
	_, err = parser.Parse(args)
	if err == nil || errors.As(err, &parseError) {
		return cli.Color, cli.Leftovers, err
	}
	require.NoError(t, err, "failed to parse command-line arguments")

	return nil, nil, nil
}
