package watermill

import (
	"context"
	"fmt"

	transportv1 "github.com/origadmin/runtime/api/gen/go/config/transport/v1"
	watermillv1 "github.com/origadmin/runtime/api/gen/go/config/transport/watermill/v1"
	"github.com/origadmin/runtime/config/protoutil"
	"github.com/origadmin/runtime/interfaces"
	"github.com/origadmin/runtime/interfaces/options"
	"github.com/origadmin/runtime/service"
)

const Protocol = "watermill"

type factory struct{}

// NewServer creates a new Watermill server (consumer).
func (f *factory) NewServer(cfg *transportv1.Server, opts ...options.Option) (interfaces.Server, error) {
	// 1. Parse the generic 'customize' field into a strongly-typed Watermill configuration.
	wmConfig, err := protoutil.NewFromStruct[watermillv1.Watermill](cfg.Customize)
	if err != nil {
		return nil, fmt.Errorf("failed to parse watermill config: %w", err)
	}

	// 2. Create the Watermill server using the parsed configuration.
	return NewServer(wmConfig, opts...)
}

// NewClient creates a new Watermill client (producer).
func (f *factory) NewClient(ctx context.Context, cfg *transportv1.Client, opts ...options.Option) (interfaces.Client, error) {
	// 1. Parse the generic 'customize' field into a strongly-typed Watermill configuration.
	wmConfig, err := protoutil.NewFromStruct[watermillv1.Watermill](cfg.Customize)
	if err != nil {
		return nil, fmt.Errorf("failed to parse watermill config: %w", err)
	}

	// 2. Create the Watermill client using the parsed configuration.
	return NewClient(wmConfig, opts...)
}

func init() {
	// Register the factory with the runtime service registry.
	service.RegisterProtocol(Protocol, &factory{})
}
