package authz

import (
	"github.com/origadmin/contrib/security"
	"github.com/origadmin/contrib/security/authz"
	"github.com/origadmin/runtime/extensions/optionutil"
	"github.com/origadmin/runtime/interfaces/options"
)

// Options holds configurations for the authz middleware.
type Options struct {
	Authorizer  authz.Authorizer
	SkipChecker security.SkipChecker
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

// fromOptions creates a new Options instance by parsing a slice of generic runtime options.
func fromOptions(opts ...options.Option) *Options {
	return optionutil.NewT[Options](opts...)
}

// NoOpSkipChecker creates a SkipChecker that never skips authorization.
func NoOpSkipChecker() security.SkipChecker {
	return security.NoOpSkipChecker()
}

// PathSkipChecker creates a SkipChecker that skips authorization for specified operation paths.
func PathSkipChecker(skipPaths ...string) security.SkipChecker {
	return security.PathSkipChecker(skipPaths...)
}
