package authn

import (
	"github.com/origadmin/contrib/security"
	"github.com/origadmin/contrib/security/authn"
	"github.com/origadmin/contrib/security/skip"
	"github.com/origadmin/runtime/extensions/optionutil"
	"github.com/origadmin/runtime/interfaces/options"
	"github.com/origadmin/runtime/log"
)

// Options holds configurations for the authn middleware, parsed from a generic options slice.
type Options struct {
	Authenticator authn.Authenticator
	Skipper       security.Skipper
	Logger        log.Logger
}

// WithAuthenticator provides an Authenticator via a runtime option.
func WithAuthenticator(authenticator authn.Authenticator) options.Option {
	return optionutil.Update(func(o *Options) {
		o.Authenticator = authenticator
	})
}

// WithSkipper provides a Skipper via a runtime option.
func WithSkipper(skipChecker security.Skipper) options.Option {
	return optionutil.Update(func(o *Options) {
		o.Skipper = skipChecker
	})
}

// WithLogger sets the logger for the middleware.
func WithLogger(logger log.Logger) options.Option {
	return log.WithLogger(logger)
}

// fromOptions creates a new Options instance by parsing a slice of generic runtime options.
func fromOptions(opts []options.Option) *Options {
	o := &Options{}
	optionutil.Apply(o, opts...)

	// CORRECTED: Pass the slice directly without the variadic '...' operator.
	o.Logger = log.FromOptions(opts)

	return o
}

// NoopSkipper creates a Skipper that never skips authentication.
// This is the default behavior.
func NoopSkipper() security.Skipper {
	return skip.Noop()
}

// PathSkipper creates a Skipper that skips authentication for specified operation paths.
// This is provided for convenience, delegating to the common helper.
func PathSkipper(skipPaths ...string) security.Skipper {
	return skip.Path(skipPaths...)
}
