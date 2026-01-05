// Copyright 2021-2026 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package main

const (
	newPackageTime = 1
	testTimesPath  = "test-times.json"
)

type testTime struct {
	Package string  `json:"package" xml:"name,attr"`
	Time    float64 `json:"time" xml:"time,attr"`
}

type testTimes []testTime

func (tts testTimes) Len() int {
	return len(tts)
}

func (tts testTimes) Less(i, j int) bool {
	switch {
	case tts[i].Time > tts[j].Time:
		return true
	case tts[i].Time < tts[j].Time:
		return false
	default:
		return tts[i].Package < tts[j].Package
	}
}

func (tts testTimes) Swap(i, j int) {
	tts[i], tts[j] = tts[j], tts[i]
}

type testTimesByKind map[string]testTimes
