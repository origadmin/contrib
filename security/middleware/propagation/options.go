package propagation

import (
	"github.com/origadmin/contrib/security/principal"
	"github.com/origadmin/runtime/extensions/optionutil"
	"github.com/origadmin/runtime/interfaces/options"
	"github.com/origadmin/runtime/log"
)

// Options holds the configuration for the principal middleware.
type Options struct {
	// PropagationType determines how the principal is propagated (e.g., via gRPC metadata or HTTP headers).
	PropagationType principal.PropagationType
	// Logger is the logger instance for the middleware.
	Logger log.Logger
}

// fromOptions parses the provided options and returns an Options struct.
func fromOptions(opts []options.Option) *Options {
	o := &Options{
		// Default propagation type is gRPC metadata.
		PropagationType: principal.PropagationTypeGRPC,
	}
	// Apply functional options that directly modify the struct.
	optionutil.Apply(o, opts...)

	// CORRECTED: Pass the slice directly without the variadic '...' operator.
	o.Logger = log.FromOptions(opts)

	return o
}

// WithPropagationType sets the propagation type for the principal.
func WithPropagationType(pt principal.PropagationType) options.Option {
	return optionutil.Update(func(o *Options) {
		o.PropagationType = pt
	})
}

// WithLogger sets the logger for the middleware.
// It uses the runtime's log.WithLogger to ensure consistency.
func WithLogger(logger log.Logger) options.Option {
	return log.WithLogger(logger)
}
