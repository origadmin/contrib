package watermill

import (
	"context"
	"fmt"

	"github.com/ThreeDotsLabs/watermill"
	"github.com/ThreeDotsLabs/watermill-kafka/v2/pkg/kafka"
	"github.com/ThreeDotsLabs/watermill-nats/v2/pkg/nats"
	"github.com/ThreeDotsLabs/watermill-redisstream/pkg/redisstream"
	"github.com/ThreeDotsLabs/watermill/message"
	"github.com/ThreeDotsLabs/watermill/message/router/middleware"
	"github.com/redis/go-redis/v9"

	contribwatermill "github.com/origadmin/contrib/broker/watermill"
	watermillv1 "github.com/origadmin/runtime/api/gen/go/config/transport/watermill/v1"
	"github.com/origadmin/runtime/interfaces"
	"github.com/origadmin/runtime/interfaces/options"
	"github.com/origadmin/runtime/log"
)

// Server implements interfaces.Server for Watermill.
// It wraps a Watermill Router.
type Server struct {
	router     *message.Router
	subscriber message.Subscriber
	logger     watermill.LoggerAdapter
}

// NewServer creates a new Watermill server instance.
func NewServer(cfg *watermillv1.Watermill, opts ...options.Option) (*Server, error) {
	// Get logger from options and adapt to watermill
	logger := log.FromOptions(opts)
	wmLogger := contribwatermill.NewLoggerAdapter(logger)

	// 1. Create Subscriber based on config
	sub, err := createSubscriber(cfg, wmLogger)
	if err != nil {
		return nil, err
	}

	// 2. Create Router
	router, err := message.NewRouter(message.RouterConfig{}, wmLogger)
	if err != nil {
		// Ensure subscriber is closed if router creation fails
		_ = sub.Close()
		return nil, fmt.Errorf("failed to create watermill router: %w", err)
	}

	// Add standard middleware
	router.AddMiddleware(
		middleware.Recoverer,
		middleware.CorrelationID,
	)

	return &Server{
		router:     router,
		subscriber: sub,
		logger:     wmLogger,
	}, nil
}

// Start starts the Watermill router.
func (s *Server) Start(ctx context.Context) error {
	return s.router.Run(ctx)
}

// Stop stops the Watermill router.
func (s *Server) Stop(_ context.Context) error {
	return s.router.Close()
}

// AddHandler adds a handler to the router.
// It supports both publishing and non-publishing handlers.
func (s *Server) AddHandler(
	handlerName string,
	subscribeTopic string,
	publishTopic string,
	publisher message.Publisher,
	handlerFunc message.HandlerFunc,
) {
	if publisher != nil && publishTopic != "" {
		s.router.AddHandler(
			handlerName,
			subscribeTopic,
			s.subscriber,
			publishTopic,
			publisher,
			handlerFunc,
		)
	} else {
		// Use AddConsumerHandler for non-publishing handlers as per deprecation notice.
		// We need to adapt HandlerFunc (returns messages) to NoPublishHandlerFunc (returns error).
		// Note: AddConsumerHandler signature is (handlerName, subscribeTopic, subscriber, handlerFunc)
		// where handlerFunc is NoPublishHandlerFunc.
		s.router.AddConsumerHandler(
			handlerName,
			subscribeTopic,
			s.subscriber,
			func(msg *message.Message) error {
				_, err := handlerFunc(msg)
				return err
			},
		)
	}
}

// AddConsumerHandler adds a handler that does not publish messages.
func (s *Server) AddConsumerHandler(
	handlerName string,
	subscribeTopic string,
	handlerFunc message.NoPublishHandlerFunc,
) {
	// Use AddConsumerHandler as the correct replacement.
	s.router.AddConsumerHandler(
		handlerName,
		subscribeTopic,
		s.subscriber,
		handlerFunc,
	)
}

// createSubscriber creates a Watermill subscriber based on the configuration.
func createSubscriber(cfg *watermillv1.Watermill, logger watermill.LoggerAdapter) (message.Subscriber, error) {
	if cfg.Broker == nil {
		return nil, fmt.Errorf("broker configuration is missing")
	}

	switch cfg.Broker.Type {
	case "redis_mq":
		if cfg.Broker.RedisMq == nil {
			return nil, fmt.Errorf("redis_mq configuration is missing")
		}
		rdb := redis.NewClient(&redis.Options{
			Addr: cfg.Broker.RedisMq.Address,
		})
		return redisstream.NewSubscriber(
			redisstream.SubscriberConfig{
				Client: rdb,
			},
			logger,
		)
	case "kafka":
		if cfg.Broker.Kafka == nil {
			return nil, fmt.Errorf("kafka configuration is missing")
		}
		return kafka.NewSubscriber(
			kafka.SubscriberConfig{
				Brokers: cfg.Broker.Kafka.Addresses,
			},
			logger,
		)
	case "nats":
		if cfg.Broker.Nats == nil {
			return nil, fmt.Errorf("nats configuration is missing")
		}
		natsConfig := nats.SubscriberConfig{
			URL: cfg.Broker.Nats.Address,
		}
		if cfg.Broker.Nats.JetstreamEnabled != nil && *cfg.Broker.Nats.JetstreamEnabled {
			natsConfig.JetStream = nats.JetStreamConfig{}
		}
		return nats.NewSubscriber(natsConfig, logger)

	default:
		return nil, fmt.Errorf("unsupported broker type: %s", cfg.Broker.Type)
	}
}

var _ interfaces.Server = (*Server)(nil)
