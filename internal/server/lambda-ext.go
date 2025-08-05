// Copyright 2021-2025 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"

	"go.uber.org/zap"
)

type lambdaExt struct {
	nextEventURL string
	extensionID  string
	client       *http.Client
}

type RegisterRequest struct {
	Events []string `json:"events"`
}

type EventResponse struct {
	EventType          string `json:"eventType"`
	DeadlineMs         int64  `json:"deadlineMs"`
	RequestID          string `json:"requestId"` //nolint:tagliatelle
	InvokedFunctionArn string `json:"invokedFunctionArn"`
	Tracing            struct {
		Type  string `json:"type"`
		Value string `json:"value"`
	} `json:"tracing"`
}

const (
	extensionNameHeader  = "Lambda-Extension-Name"
	extensionIDHeader    = "Lambda-Extension-Identifier"
	registrationEndpoint = "/2020-01-01/extension/register"
	nextEventEndpoint    = "/2020-01-01/extension/event/next"
)

const maxBodySize = 1024

func registerNewLambdaExt(ctx context.Context, runtimeAPI string) (*lambdaExt, error) {
	l := lambdaExt{
		nextEventURL: fmt.Sprintf("http://%s%s", runtimeAPI, nextEventEndpoint),
		client:       &http.Client{Timeout: 10 * time.Second}, //nolint:mnd
	}
	url := fmt.Sprintf("http://%s%s", runtimeAPI, registrationEndpoint)

	registerReq := RegisterRequest{Events: []string{"SHUTDOWN"}}

	reqBody, err := json.Marshal(registerReq)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal register request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewBuffer(reqBody))
	if err != nil {
		return nil, fmt.Errorf("failed to create register request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(extensionNameHeader, "Cerbos PDP")

	resp, err := l.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to register extension: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, maxBodySize))
		return nil, fmt.Errorf("registration failed with status %d: %s", resp.StatusCode, string(body))
	}

	l.extensionID = resp.Header.Get(extensionIDHeader)

	return &l, nil
}

func (l *lambdaExt) checkShutdown(ctx context.Context) (bool, error) {
	log := zap.L().Named("lambda-ext-impl")

	req, err := http.NewRequestWithContext(ctx, "GET", l.nextEventURL, nil)
	if err != nil {
		return false, fmt.Errorf("failed to create next event request: %w", err)
	}

	req.Header.Set(extensionIDHeader, l.extensionID)

	resp, err := l.client.Do(req)
	if err != nil {
		var urlErr *url.Error
		if errors.As(err, &urlErr) && urlErr.Timeout() {
			log.Debug("Checking next event timed-out")
			return false, nil
		}
		return false, fmt.Errorf("failed to get next event: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, maxBodySize))
		return false, fmt.Errorf("get next event failed with status %d: %s", resp.StatusCode, string(body))
	}

	var event EventResponse
	if err := json.NewDecoder(resp.Body).Decode(&event); err != nil {
		return false, fmt.Errorf("failed to decode event: %w", err)
	}

	return event.EventType == "SHUTDOWN", nil
}
