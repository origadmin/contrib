/*
 * Copyright (c) 2024 OrigAdmin. All rights reserved.
 */

package redis

import (
	"context"
	"fmt"

	"github.com/redis/go-redis/v9"

	"github.com/origadmin/toolkits/queue"
)

type subscription struct {
	sub   *redis.PubSub
	queue string
	topic string
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
	return 0, nil
}

func (s *subscription) Delivered() (uint64, error) {
	return 0, nil
}

func (s *subscription) Dropped() (uint64, error) {
	return 0, nil
}

func (s *subscription) ClearMaxPending() error {
	return nil
}

func (s *subscription) MaxPending() (int, int, error) {
	return 0, 0, nil
}

func (s *subscription) Unsubscribe() error {
	return s.sub.Unsubscribe(context.Background())
}

func (s *subscription) Topic() string {
	return s.topic
}

func (s *subscription) IsQueue() bool {
	return s.queue != ""
}

func (s *subscription) IsActive() bool {
	return true

}

var (
	_ queue.Subscription = (*subscription)(nil)
)
