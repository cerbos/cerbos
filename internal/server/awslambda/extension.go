// Copyright 2021-2025 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package awslambda

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path"
	"strings"
	"time"

	"github.com/cerbos/cerbos/internal/config"
	"github.com/cerbos/cerbos/internal/run"
	"github.com/cerbos/cerbos/internal/server"
)

type lambdaExt struct {
	client      *http.Client
	runtimeAPI  string
	extensionID string
}

type RegisterRequest struct {
	Events []string `json:"events"`
}

type EventResponse struct {
	Tracing struct {
		Type  string `json:"type"`
		Value string `json:"value"`
	} `json:"tracing"`
	EventType          string `json:"eventType"`
	RequestID          string `json:"requestId"` //nolint:tagliatelle
	InvokedFunctionArn string `json:"invokedFunctionArn"`
	DeadlineMs         int64  `json:"deadlineMs"`
}

const (
	extensionNameHeader  = "Lambda-Extension-Name"
	extensionIDHeader    = "Lambda-Extension-Identifier"
	extensionErrorType   = "Lambda-Extension-Function-Error-Type"
	registrationEndpoint = "/2020-01-01/extension/register"
	nextEventEndpoint    = "/2020-01-01/extension/event/next"
	exitErrorEndpoint    = "/2020-01-01/extension/exit/error"
)

const maxBodySize = 1024

func RegisterNewExtension(ctx context.Context, runtimeAPI string) (*lambdaExt, error) {
	l := lambdaExt{
		runtimeAPI: runtimeAPI,
		client:     &http.Client{Timeout: 0}, //nolint:mnd
	}
	url := fmt.Sprintf("http://%s%s", runtimeAPI, registrationEndpoint)

	registerReq := RegisterRequest{Events: []string{"SHUTDOWN"}}

	reqBody, err := json.Marshal(registerReq)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal register request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewBuffer(reqBody))
	if err != nil {
		return nil, fmt.Errorf("failed to create register request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(extensionNameHeader, path.Base(os.Args[0]))

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

func (l *lambdaExt) CheckShutdown(ctx context.Context) (bool, error) {
	nextEventURL := fmt.Sprintf("http://%s%s", l.runtimeAPI, nextEventEndpoint)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, nextEventURL, nil)
	if err != nil {
		return false, fmt.Errorf("failed to create next event request: %w", err)
	}

	req.Header.Set(extensionIDHeader, l.extensionID)

	resp, err := l.client.Do(req)
	if err != nil {
		return false, fmt.Errorf("failed to get next event: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, maxBodySize))
		if len(body) == maxBodySize {
			_, _ = io.Copy(io.Discard, resp.Body)
		}
		return false, fmt.Errorf("get next event failed with status %d: %s", resp.StatusCode, string(body))
	}

	var event EventResponse
	if err := json.NewDecoder(resp.Body).Decode(&event); err != nil {
		return false, fmt.Errorf("failed to decode event: %w", err)
	}

	return event.EventType == "SHUTDOWN", nil
}

func (l *lambdaExt) ReportError(ctx context.Context, err error) error {
	url := fmt.Sprintf("http://%s%s", l.runtimeAPI, exitErrorEndpoint)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, strings.NewReader(err.Error()))
	if err != nil {
		return fmt.Errorf("failed to create exit error request: %w", err)
	}

	req.Header.Set(extensionIDHeader, l.extensionID)
	req.Header.Set(extensionErrorType, "Extension.UnknownError")

	resp, err := l.client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to report error: %w", err)
	}

	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()

	return nil
}

func WaitForReady(ctx context.Context) error {
	var conf server.Conf
	if err := config.GetSection(&conf); err != nil {
		return fmt.Errorf("failed to obtain server config; %w", err)
	}
	protocol := "http"
	if conf.TLS != nil && conf.TLS.Cert != "" && conf.TLS.Key != "" {
		protocol = "https"
	}
	httpAddr := fmt.Sprintf("%s://%s", protocol, conf.HTTPListenAddr)
	const timeout = 5 * time.Second
	ctx, cancelFunc := context.WithTimeout(ctx, timeout)
	defer cancelFunc()
	if err := run.WaitForReady(ctx, nil, httpAddr); err != nil {
		return err
	}
	return nil
}
