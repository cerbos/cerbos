// Copyright 2021 Zenauth Ltd.

package common

import (
	"context"
	"fmt"
	"sync"

	"github.com/cerbos/cerbos/internal/compile"
)

type Notifier struct {
	mu         sync.RWMutex
	notifyChan chan<- compile.Notification
}

func NewNotifier() *Notifier {
	return new(Notifier)
}

func (n *Notifier) SetNotificationChannel(ch chan<- compile.Notification) {
	n.mu.Lock()
	defer n.mu.Unlock()

	n.notifyChan = ch
}

func (n *Notifier) NotifyIncrementalUpdate(ctx context.Context, change *compile.Incremental) error {
	return n.notify(ctx, compile.Notification{FullRecompile: false, Payload: change})
}

func (n *Notifier) NotifyFullUpdate(ctx context.Context) error {
	return n.notify(ctx, compile.Notification{FullRecompile: true})
}

func (n *Notifier) notify(ctx context.Context, notification compile.Notification) error {
	n.mu.RLock()
	notifyChan := n.notifyChan //nolint:ifshort
	n.mu.RUnlock()

	if notifyChan != nil {
		select {
		case <-ctx.Done():
			return fmt.Errorf("failed to send notification: %w", ctx.Err())
		case notifyChan <- notification:
		}
	}

	return nil
}
