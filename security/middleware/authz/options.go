package authz

import (
	"github.com/origadmin/contrib/security"
	"github.com/origadmin/contrib/security/authz"
	"github.com/origadmin/contrib/security/skip"
	"github.com/origadmin/runtime/context"
	"github.com/origadmin/runtime/extensions/optionutil"
	"github.com/origadmin/runtime/interfaces/options"
	"github.com/origadmin/runtime/log"
)

// Options holds configurations for the authz middleware.
type Options struct {
	Authorizer authz.Authorizer
	RuleSpec   RuleSpecFunc
	Skipper    security.Skipper
	Logger     log.Logger
}

// RuleSpecFunc is a function that returns a RuleSpec for a given request.
type RuleSpecFunc func(ctx context.Context, p security.Principal, req security.Request) authz.RuleSpec

// WithRuleSpec provides a RuleSpecFunc via a runtime option.
func WithRuleSpec(ruleSpecFunc RuleSpecFunc) options.Option {
	return optionutil.Update(func(o *Options) {
		o.RuleSpec = ruleSpecFunc
	})
}

// WithAuthorizer provides an Authorizer via a runtime option.
func WithAuthorizer(authorizer authz.Authorizer) options.Option {
	return optionutil.Update(func(o *Options) {
		o.Authorizer = authorizer
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

// NoopSkipper creates a Skipper that never skips authorization.
func NoopSkipper() security.Skipper {
	return skip.Noop()
}

// PathSkipper creates a Skipper that skips authorization for specified operation paths.
func PathSkipper(skipPaths ...string) security.Skipper {
	return skip.Path(skipPaths...)
}
