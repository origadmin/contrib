// Package watermill implements the functions, types, and interfaces for the module.
package watermill

import (
	"fmt"

	"github.com/ThreeDotsLabs/watermill"
	"github.com/ThreeDotsLabs/watermill-kafka/v3/pkg/kafka"
	"github.com/ThreeDotsLabs/watermill-nats/v2/pkg/nats"
	"github.com/ThreeDotsLabs/watermill-redisstream/pkg/redisstream"
	"github.com/ThreeDotsLabs/watermill/message"
	"github.com/redis/go-redis/v9"

	watermillv1 "github.com/origadmin/runtime/api/gen/go/config/transport/watermill/v1"
)

func NewPublisher(cfg *watermillv1.Watermill, logger watermill.LoggerAdapter) (message.Publisher, error) {
	return createPublisher(cfg, logger)
}

// createPublisher creates a Watermill publisher based on the configuration.
func createPublisher(cfg *watermillv1.Watermill, logger watermill.LoggerAdapter) (message.Publisher, error) {
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
		return redisstream.NewPublisher(
			redisstream.PublisherConfig{
				Client: rdb,
			},
			logger,
		)
	case "kafka":
		if cfg.Broker.Kafka == nil {
			return nil, fmt.Errorf("kafka configuration is missing")
		}
		return kafka.NewPublisher(
			kafka.PublisherConfig{
				Brokers: cfg.Broker.Kafka.Addresses,
			},
			logger,
		)
	case "nats":
		if cfg.Broker.Nats == nil {
			return nil, fmt.Errorf("nats configuration is missing")
		}
		natsConfig := nats.PublisherConfig{
			URL: cfg.Broker.Nats.Address,
		}
		if cfg.Broker.Nats.JetstreamEnabled != nil && *cfg.Broker.Nats.JetstreamEnabled {
			natsConfig.JetStream = nats.JetStreamConfig{}
		}
		return nats.NewPublisher(natsConfig, logger)

	default:
		return nil, fmt.Errorf("unsupported broker type: %s", cfg.Broker.Type)
	}
}
