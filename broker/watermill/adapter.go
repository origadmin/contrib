package watermill

import (
	"context"
	"fmt"

	"github.com/ThreeDotsLabs/watermill"
	"github.com/ThreeDotsLabs/watermill/message"

	"github.com/origadmin/runtime/api/gen/go/config/transport/watermill/v1"
	runtimebroker "github.com/origadmin/runtime/broker"
	"github.com/origadmin/runtime/log"
)

// LoggerAdapter adapts runtime/log.Logger to watermill.LoggerAdapter.
type LoggerAdapter struct {
	logger log.Logger
	helper *log.Helper
}

// NewLoggerAdapter creates a new watermill.LoggerAdapter that wraps runtime logger.
// If logger is nil, it uses the default logger from runtime/log.
func NewLoggerAdapter(logger log.Logger) watermill.LoggerAdapter {
	if logger == nil {
		logger = log.DefaultLogger
	}
	l := log.With(logger, "component", "watermill")
	return &LoggerAdapter{
		logger: l,
		helper: log.NewHelper(l),
	}
}

func (l *LoggerAdapter) fieldsToArgs(fields watermill.LogFields) []interface{} {
	args := make([]interface{}, 0, len(fields)*2)
	for k, v := range fields {
		args = append(args, k, v)
	}
	return args
}

func (l *LoggerAdapter) Error(msg string, err error, fields watermill.LogFields) {
	args := l.fieldsToArgs(fields)
	args = append(args, "msg", msg, "err", err)
	l.helper.Errorw(args...)
}

func (l *LoggerAdapter) Info(msg string, fields watermill.LogFields) {
	args := l.fieldsToArgs(fields)
	args = append(args, "msg", msg)
	l.helper.Infow(args...)
}

func (l *LoggerAdapter) Debug(msg string, fields watermill.LogFields) {
	args := l.fieldsToArgs(fields)
	args = append(args, "msg", msg)
	l.helper.Debugw(args...)
}

func (l *LoggerAdapter) Trace(msg string, fields watermill.LogFields) {
	// runtime/log doesn't have Trace, so we map it to Debug.
	args := l.fieldsToArgs(fields)
	args = append(args, "msg", msg)
	l.helper.Debugw(args...)
}

func (l *LoggerAdapter) With(fields watermill.LogFields) watermill.LoggerAdapter {
	newLogger := log.With(l.logger, l.fieldsToArgs(fields)...)
	return &LoggerAdapter{
		logger: newLogger,
		helper: log.NewHelper(newLogger),
	}
}

// Broker implements the runtime/broker.Broker interface by adapting Watermill.
type Broker struct {
	publisher  message.Publisher
	subscriber message.Subscriber
	logger     watermill.LoggerAdapter
}

// NewBroker creates a new Broker from configuration.
func NewBroker(cfg *watermillv1.Watermill, logger log.Logger) (*Broker, error) {
	wmLogger := NewLoggerAdapter(logger)

	// Create Publisher
	pub, err := createPublisher(cfg, wmLogger)
	if err != nil {
		return nil, err
	}

	// Create Subscriber
	sub, err := createSubscriber(cfg, wmLogger)
	if err != nil {
		_ = pub.Close()
		return nil, err
	}

	return &Broker{
		publisher:  pub,
		subscriber: sub,
		logger:     wmLogger,
	}, nil
}

// NewBrokerFromComponents creates a Broker from existing Watermill Publisher and Subscriber.
func NewBrokerFromComponents(publisher message.Publisher, subscriber message.Subscriber, logger log.Logger) *Broker {
	wmLogger := NewLoggerAdapter(logger)
	return &Broker{
		publisher:  publisher,
		subscriber: subscriber,
		logger:     wmLogger,
	}
}

// Publish publishes messages to the specified topic.
func (b *Broker) Publish(_ context.Context, topic string, messages ...*runtimebroker.Message) error {
	if b.publisher == nil {
		return fmt.Errorf("publisher is not initialized")
	}

	wmMessages := make([]*message.Message, len(messages))
	for i, msg := range messages {
		wmMessages[i] = b.toWatermillMessage(msg)
	}

	return b.publisher.Publish(topic, wmMessages...)
}

// Subscribe subscribes to messages from the specified topic.
func (b *Broker) Subscribe(ctx context.Context, topic string) (<-chan *runtimebroker.Message, error) {
	if b.subscriber == nil {
		return nil, fmt.Errorf("subscriber is not initialized")
	}

	wmChan, err := b.subscriber.Subscribe(ctx, topic)
	if err != nil {
		return nil, err
	}

	resultChan := make(chan *runtimebroker.Message, 100)

	go func() {
		defer close(resultChan)
		for wmMsg := range wmChan {
			resultChan <- b.fromWatermillMessage(wmMsg)
		}
	}()

	return resultChan, nil
}

// Close closes both the Publisher and Subscriber.
func (b *Broker) Close() error {
	var lastErr error

	if b.publisher != nil {
		if err := b.publisher.Close(); err != nil {
			lastErr = err
		}
	}

	if b.subscriber != nil {
		if err := b.subscriber.Close(); err != nil {
			lastErr = err
		}
	}

	return lastErr
}

// toWatermillMessage converts runtime/broker.Message to Watermill's message.Message.
func (b *Broker) toWatermillMessage(msg *runtimebroker.Message) *message.Message {
	if msg == nil {
		return nil
	}
	wmMsg := message.NewMessage(msg.ID, msg.Payload)
	wmMsg.Metadata = msg.Metadata
	return wmMsg
}

// fromWatermillMessage converts Watermill's message.Message to runtime/broker.Message.
func (b *Broker) fromWatermillMessage(msg *message.Message) *runtimebroker.Message {
	if msg == nil {
		return nil
	}
	return &runtimebroker.Message{
		ID:       msg.UUID,
		Metadata: msg.Metadata,
		Payload:  msg.Payload,
	}
}

// Ensure Broker implements runtime/broker.Broker interface.
var _ runtimebroker.Broker = (*Broker)(nil)
