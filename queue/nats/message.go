/*
 * Copyright (c) 2024 OrigAdmin. All rights reserved.
 */

package nats

import (
	"context"

	"github.com/nats-io/nats.go"

	"github.com/origadmin/toolkits/queue"
)

type deliverMessage struct {
	message *queue.Message
	natsMsg *nats.Msg
}

func (d *deliverMessage) Message() *queue.Message {
	return d.message
}

func (d *deliverMessage) Ack(ctx context.Context) error {
	return d.natsMsg.Ack()
}

func (d *deliverMessage) Nack(ctx context.Context) error {
	return d.natsMsg.Nak()
}

var (
	_ queue.DeliverMessage = (*deliverMessage)(nil)
)
