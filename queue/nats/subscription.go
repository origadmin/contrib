/*
 * Copyright (c) 2024 OrigAdmin. All rights reserved.
 */

package nats

import (
	"fmt"

	"github.com/nats-io/nats.go"

	"github.com/origadmin/toolkits/queue"
)

type subscription struct {
	sub   *nats.Subscription
	queue string
}

func (s *subscription) Queue() (string, bool) {
	return s.queue, s.IsQueue()
}

func (s *subscription) Pause() error {
	// NATS doesn't support pausing subscriptions
	return fmt.Errorf("pause not supported")
}

func (s *subscription) Resume() error {
	// NATS doesn't support resuming subscriptions
	return fmt.Errorf("resume not supported")
}

func (s *subscription) HandlerMessage(handler func(*queue.Message)) error {
	// NATS doesn't support changing handlers after subscription
	return fmt.Errorf("changing handler not supported")
}

func (s *subscription) Pending() (int, error) {
	p, _, err := s.sub.Pending()
	return int(p), err
}

func (s *subscription) Delivered() (uint64, error) {
	d, err := s.sub.Delivered()
	return uint64(d), err
}

func (s *subscription) Dropped() (uint64, error) {
	d, err := s.sub.Dropped()
	return uint64(d), err
}

func (s *subscription) ClearMaxPending() error {
	return s.sub.ClearMaxPending()
}

func (s *subscription) MaxPending() (int, int, error) {
	return s.sub.MaxPending()
}

func (s *subscription) Unsubscribe() error {
	return s.sub.Unsubscribe()
}

func (s *subscription) Topic() string {
	return s.sub.Subject
}

func (s *subscription) IsQueue() bool {
	return s.queue != ""
}

func (s *subscription) IsActive() bool {
	return s.sub.IsValid()
}

var (
	_ queue.Subscription = (*subscription)(nil)
)
