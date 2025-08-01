/*
 * Copyright (c) 2024 OrigAdmin. All rights reserved.
 */

package nats

import (
	"context"
	"time"

	"github.com/nats-io/nats.go"

	"github.com/origadmin/toolkits/queue"
)

type messageQueue struct {
	conn    *nats.Conn
	subject string
}

func (mq *messageQueue) Publish(ctx context.Context, payload string) (string, error) {
	err := mq.conn.Publish(mq.subject, []byte(payload))
	return "", err // NATS doesn't provide a message ID on publish
}

func (mq *messageQueue) Subscribe(ctx context.Context, handler func(queue.DeliverMessage)) error {
	_, err := mq.conn.Subscribe(mq.subject, func(msg *nats.Msg) {
		handler(decodeMsg(msg))
	})
	return err
}

func decodeMsg(msg *nats.Msg) *deliverMessage {
	return &deliverMessage{
		message: &queue.Message{
			ID:        msg.Reply,
			Topic:     msg.Subject,
			Timestamp: time.Now(),
			Payload:   string(msg.Data),
		},
		natsMsg: msg,
	}
}

func (mq *messageQueue) Size() int64 {
	// NATS doesn't provide a way to get queue size
	return -1
}

var (
	_ queue.MessageQueue = (*messageQueue)(nil)
)
