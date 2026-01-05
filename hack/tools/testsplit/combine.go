// Copyright 2021-2026 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/json"
	"encoding/xml"
	"fmt"
	"os"
	"sort"
)

type combineCmd struct {
	Kinds []string
	Total int
}

func (cmd *combineCmd) Run() error {
	result := make(testTimesByKind, len(cmd.Kinds))

	for _, kind := range cmd.Kinds {
		for i := 0; i < cmd.Total; i++ {
			report, err := readReport(kind, i)
			if err != nil {
				return err
			}

			result[kind] = append(result[kind], report.TestTimes...)
		}

		sort.Sort(result[kind])
	}

	data, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal test times: %w", err)
	}

	err = os.WriteFile(testTimesPath, data, 0o600) //nolint:mnd
	if err != nil {
		return fmt.Errorf("failed to write test times: %w", err)
	}

	return nil
}

type junitReport struct {
	XMLName   xml.Name   `xml:"testsuites"`
	TestTimes []testTime `xml:"testsuite"`
}

func readReport(kind string, index int) (junitReport, error) {
	var report junitReport

	path := fmt.Sprintf("junit.%s.%d.xml", kind, index)
	data, err := os.ReadFile(path)
	if err != nil {
		return report, fmt.Errorf("failed to read JUnit report %q: %w", path, err)
	}

	err = xml.Unmarshal(data, &report)
	if err != nil {
		return report, fmt.Errorf("failed to unmarshal JUnit report %q: %w", path, err)
	}

	return report, nil
}
