// Copyright 2021-2025 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package run

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"time"
)

const (
	requestTimeout = 100 * time.Millisecond
	retryInterval  = 141 * time.Millisecond
)

func WaitForReady(ctx context.Context, errors <-chan error, client *http.Client, httpAddr string) error {
	healthURL := fmt.Sprintf("%s/_cerbos/health", httpAddr)
	lastErr := checkHealth(client, healthURL)
	if lastErr == nil {
		return nil
	}

	ticker := time.NewTicker(retryInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return lastErr
		case err := <-errors:
			return err
		case <-ticker.C:
			lastErr = checkHealth(client, healthURL)
			if lastErr == nil {
				return nil
			}
		}
	}
}

func checkHealth(client *http.Client, healthURL string) error {
	ctx, cancelFunc := context.WithTimeout(context.Background(), requestTimeout)
	defer cancelFunc()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, healthURL, http.NoBody)
	if err != nil {
		return err
	}

	resp, err := client.Do(req)
	if err != nil {
		return err
	}

	defer func() {
		if resp.Body != nil {
			_, _ = io.Copy(io.Discard, resp.Body)
			_ = resp.Body.Close()
		}
	}()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("received status %q", resp.Status)
	}

	return nil
}
