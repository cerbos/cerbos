// Copyright 2021-2025 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package internal

import (
	"fmt"
	"net/url"
)

const (
	FeedbackMsg  = "It looks like an unexpected error happened. Please use the link below to report it to Cerbos developers."
	baseURL      = "https://github.com/cerbos/cerbos/issues/new"
	FeedbackLink = baseURL + "/choose"
)

func GenerateFeedbackLink(header, version, commitSHA string, stack []byte) string {
	u, err := url.Parse(baseURL)
	if err != nil {
		panic(err) // this should never happen
	}
	q := u.Query()
	q.Set("labels", "bug")
	q.Set("title", header)
	var body string
	if version != "" {
		body += fmt.Sprintf("Version: %s\n", version)
	}
	if commitSHA != "" {
		body += fmt.Sprintf("Commit: %s\n", commitSHA)
	}
	if stack != nil {
		body += fmt.Sprintf("\nStack:\n```\n%s\n```\n", stack)
	}
	q.Set("body", body)
	u.RawQuery = q.Encode()
	return fmt.Sprint(u)
}
