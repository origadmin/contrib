/*
 * Copyright (c) 2024 OrigAdmin. All rights reserved.
 */

package other

import (
	"context"

	"github.com/nsqio/go-nsq"

	"github.com/origadmin/toolkits/queue"
)

type deliverMessage struct {
	message *queue.Message
	nsqMsg  *nsq.Message
}

func (d deliverMessage) Message() *queue.Message {
	return d.message
}

func (d deliverMessage) Ack(ctx context.Context) error {
	d.nsqMsg.Finish()
	return nil
}

func (d deliverMessage) Nack(ctx context.Context) error {
	d.nsqMsg.Requeue(0)
	return nil
}
