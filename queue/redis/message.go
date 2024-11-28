/*
 * Copyright (c) 2024 OrigAdmin. All rights reserved.
 */

package redis

import (
	"context"

	"github.com/redis/go-redis/v9"

	"github.com/origadmin/toolkits/errors"
	"github.com/origadmin/toolkits/queue"
)

type deliverMessage struct {
	message  *queue.Message
	redisMsg *redis.Message
}

func (d *deliverMessage) Message() *queue.Message {
	return d.message
}

func (d *deliverMessage) Ack(ctx context.Context) error {
	return errors.New("not supported")
}

func (d *deliverMessage) Nack(ctx context.Context) error {
	return errors.New("not supported")
}

var (
	_ queue.DeliverMessage = (*deliverMessage)(nil)
)
