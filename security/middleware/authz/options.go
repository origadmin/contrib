package authz

import (
	"github.com/origadmin/contrib/security"
	"github.com/origadmin/contrib/security/authz"
	"github.com/origadmin/runtime/extensions/optionutil"
	"github.com/origadmin/runtime/interfaces/options"
	"github.com/origadmin/runtime/log"
)

// Options holds configurations for the authz middleware.
type Options struct {
	Authorizer  authz.Authorizer
	SkipChecker security.SkipChecker
	Logger      log.Logger
}

// WithAuthorizer provides an Authorizer via a runtime option.
func WithAuthorizer(authorizer authz.Authorizer) options.Option {
	return optionutil.Update(func(o *Options) {
		o.Authorizer = authorizer
	})
}

// WithSkipChecker provides a SkipChecker via a runtime option.
func WithSkipChecker(skipChecker security.SkipChecker) options.Option {
	return optionutil.Update(func(o *Options) {
		o.SkipChecker = skipChecker
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

// NoOpSkipChecker creates a SkipChecker that never skips authorization.
func NoOpSkipChecker() security.SkipChecker {
	return security.NoOpSkipChecker()
}

// PathSkipChecker creates a SkipChecker that skips authorization for specified operation paths.
func PathSkipChecker(skipPaths ...string) security.SkipChecker {
	return security.PathSkipChecker(skipPaths...)
}
