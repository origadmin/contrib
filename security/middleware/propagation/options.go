package propagation

import (
	"github.com/origadmin/contrib/security/principal"
	"github.com/origadmin/runtime/extensions/optionutil"
	"github.com/origadmin/runtime/interfaces/options"
)

// Options holds the configuration for the principal middleware.
type Options struct {
	// PropagationType determines how the principal is propagated (e.g., via gRPC metadata or HTTP headers).
	PropagationType principal.PropagationType
}

// fromOptions parses the provided options and returns an Options struct.
func fromOptions(opts []options.Option) *Options {
	o := &Options{
		// Default propagation type is gRPC metadata.
		PropagationType: principal.PropagationTypeGRPC,
	}
	optionutil.Apply(o, opts...)
	return o
}

// WithPropagationType sets the propagation type for the principal.
func WithPropagationType(pt principal.PropagationType) options.Option {
	return optionutil.Update(func(o *Options) {
		o.PropagationType = pt
	})
}
