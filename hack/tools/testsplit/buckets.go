// Copyright 2021-2025 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package main

type testBucket struct {
	Packages  []string
	TotalTime float64
}

func (tb *testBucket) Add(time testTime) {
	tb.Packages = append(tb.Packages, time.Package)
	tb.TotalTime += time.Time
}

type testBuckets []testBucket

func (tbs testBuckets) LeastFull() *testBucket {
	var result *testBucket

	for i := range tbs {
		if result == nil || result.TotalTime > tbs[i].TotalTime {
			result = &tbs[i]
		}
	}

	return result
}
