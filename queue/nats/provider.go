/*
 * Copyright (c) 2024 OrigAdmin. All rights reserved.
 */

package nats

import (
	"context"
	"fmt"
	"time"

	"github.com/goexts/generic/configure"
	"github.com/nats-io/nats.go"

	"github.com/origadmin/toolkits/queue"
)

type Setting settings.Setting[*nats.Options]

type Provider struct {
	conn *nats.Conn
}

func (p *Provider) MessageQueue(subject string) (queue.MessageQueue, error) {
	return &messageQueue{conn: p.conn, subject: subject}, nil
}

func (p *Provider) PublishToTopic(ctx context.Context, topic string, payload string) error {
	return p.conn.Publish(topic, []byte(payload))
}

func (p *Provider) SubscribeToTopic(ctx context.Context, topic string, handler func(queue.DeliverMessage)) (queue.Subscription, error) {
	sub, err := p.conn.Subscribe(topic, func(msg *nats.Msg) {
		handler(decodeMsg(msg))
	})
	if err != nil {
		return nil, fmt.Errorf("failed to subscribe: %w", err)
	}
	return &subscription{sub: sub}, nil
}

func (p *Provider) RequestReply(ctx context.Context, topic string, payload string) (*queue.Message, error) {
	msg, err := p.conn.RequestWithContext(ctx, topic, []byte(payload))
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	return &queue.Message{
		ID:        msg.Reply,
		Topic:     msg.Subject,
		Timestamp: time.Now(),
		Payload:   string(msg.Data),
	}, nil
}

func (p *Provider) QueueSubscribe(ctx context.Context, subject string, handler func(queue.DeliverMessage)) (queue.Subscription, error) {
	queueName := fmt.Sprintf("queue_%s", subject)
	sub, err := p.conn.QueueSubscribe(subject, queueName, func(msg *nats.Msg) {
		handler(decodeMsg(msg))
	})
	if err != nil {
		return nil, fmt.Errorf("failed to queue subscribe: %w", err)
	}
	return &subscription{sub: sub, queue: queueName}, nil
}

func NewProvider(url string, options ...nats.Option) (queue.MessageQueueProvider, error) {
	return NewNatsProvider(url, options...)
}

func NewNatsProvider(url string, options ...nats.Option) (*Provider, error) {
	// Add default options
	opts := []nats.Option{
		nats.ReconnectWait(time.Second * 5),
		nats.MaxReconnects(-1), // 无限重连
		nats.DisconnectErrHandler(func(nc *nats.Conn, err error) {
			// Here you can add logging when you disconnect
		}),
		nats.ReconnectHandler(func(nc *nats.Conn) {
			// You can add a log of the successful connection here
		}),
	}

	// Merge user provided options
	opts = append(opts, options...)
	conn, err := nats.Connect(url, opts...)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to NATS: %w", err)
	}
	return &Provider{conn: conn}, nil
}

func (p *Provider) Close() error {
	p.conn.Close()
	return nil
}

var (
	_ queue.MessageQueueProvider = (*Provider)(nil)
)
