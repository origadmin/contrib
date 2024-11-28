/*
 * Copyright (c) 2024 OrigAdmin. All rights reserved.
 */

package redis

import (
	"context"
	"strconv"

	"github.com/origadmin/toolkits/queue"
)

// MessageQueue implements the MessageQueue interface using Redis.
type MessageQueue struct {
	provider *Provider
	subject  string
}

// Publish a message to the queue.
func (q *MessageQueue) Publish(ctx context.Context, payload string) (string, error) {
	result, err := q.provider.client.Publish(ctx, q.subject, payload).Result()
	if err != nil {
		return "", err
	}
	return strconv.FormatInt(result, 10), nil
}

// Subscribe to the queue and process the messages.
func (q *MessageQueue) Subscribe(ctx context.Context, handler func(queue.DeliverMessage)) error {
	topic, err := q.provider.SubscribeToTopic(ctx, q.subject, handler)
	if err != nil {
		return err
	}
	return topic.Unsubscribe()
}

// Size returns the number of messages in the queue.
func (q *MessageQueue) Size() int64 {
	// Redis 不直接支持队列大小，这里可以使用其他方法或近似值
	return 0
}
