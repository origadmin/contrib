/*
 * Copyright (c) 2024 OrigAdmin. All rights reserved.
 */

package redis

import (
	"context"
	"strconv"
	"time"

	"github.com/redis/go-redis/v9"

	"github.com/origadmin/toolkits/queue"
)

// Provider implements the MessageQueueProvider using Redis.
type Provider struct {
	client *redis.Client
}

// NewProvider creates a new Provider.
func NewProvider(addr string, password string, db int) (*Provider, error) {
	client := redis.NewClient(&redis.Options{
		Addr:     addr,
		Password: password,
		DB:       db,
	})

	_, err := client.Ping(context.Background()).Result()
	if err != nil {
		return nil, err
	}

	return &Provider{client: client}, nil
}

// MessageQueue obtains the corresponding MessageQueue based on subject.
func (p *Provider) MessageQueue(subject string) (queue.MessageQueue, error) {
	return &MessageQueue{provider: p, subject: subject}, nil
}

// PublishToTopic publishes a message to the specified topic.
func (p *Provider) PublishToTopic(ctx context.Context, topic string, payload string) error {
	return p.client.Publish(ctx, topic, payload).Err()
}

// SubscribeToTopic subscribes to messages for a specified topic.
func (p *Provider) SubscribeToTopic(ctx context.Context, topic string, handler func(queue.DeliverMessage)) (queue.Subscription, error) {
	pubsub := p.client.Subscribe(ctx, topic)
	go func() {
		for msg := range pubsub.Channel() {
			handler(&deliverMessage{
				redisMsg: msg,
				message: &queue.Message{
					ID:        msg.Channel,
					Topic:     msg.Channel,
					Timestamp: time.Now(),
					Payload:   msg.Payload,
				},
			})
		}
	}()
	return &subscription{
		sub:   pubsub,
		topic: topic,
	}, nil
}

// RequestReply sends a request and waits for a response.
func (p *Provider) RequestReply(ctx context.Context, topic string, payload string) (*queue.Message, error) {
	resp, err := p.client.Publish(ctx, topic, payload).Result()
	if err != nil {
		return nil, err
	}

	return &queue.Message{
		ID:        strconv.FormatInt(resp, 10),
		Topic:     topic,
		Timestamp: time.Now(),
		Payload:   "Response",
	}, nil
}

// QueueSubscribe creates a queue subscription.
func (p *Provider) QueueSubscribe(ctx context.Context, subject string, handler func(queue.DeliverMessage)) (queue.Subscription, error) {
	return p.SubscribeToTopic(ctx, subject, handler)
}

// Close closes all MessageQueue connections.
func (p *Provider) Close() error {
	return p.client.Close()
}
