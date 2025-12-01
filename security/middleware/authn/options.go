package authn

import (
	"github.com/origadmin/contrib/security" // Import the security package
	"github.com/origadmin/contrib/security/authn"
	"github.com/origadmin/contrib/security/principal"
	"github.com/origadmin/runtime/extensions/optionutil"
	"github.com/origadmin/runtime/interfaces/options"
)

// Options holds configurations for the authn middleware, parsed from a generic options slice.
type Options struct {
	Authenticator   authn.Authenticator
	SkipChecker     security.SkipChecker // Use the common SkipChecker
	PropagationType principal.PropagationType
}

// WithAuthenticator provides an Authenticator via a runtime option.
func WithAuthenticator(authenticator authn.Authenticator) options.Option {
	return optionutil.Update(func(o *Options) {
		o.Authenticator = authenticator
	})
}

// WithSkipChecker provides a SkipChecker via a runtime option.
func WithSkipChecker(skipChecker security.SkipChecker) options.Option { // Use the common SkipChecker
	return optionutil.Update(func(o *Options) {
		o.SkipChecker = skipChecker
	})
}

// WithPropagationType provides a PropagationType via a runtime option.
func WithPropagationType(pt principal.PropagationType) options.Option {
	return optionutil.Update(func(o *Options) {
		o.PropagationType = pt
	})
}

// fromOptions creates a new Options instance by parsing a slice of generic runtime options.
// This is an internal helper for the factory.
func fromOptions(opts ...options.Option) *Options {
	return optionutil.NewT[Options](opts...)
}

// NoOpSkipChecker creates a SkipChecker that never skips authentication.
// This is the default behavior.
func NoOpSkipChecker() security.SkipChecker { // Use the common SkipChecker
	return security.NoOpSkipChecker() // Delegate to the common helper
}

// PathSkipChecker creates a SkipChecker that skips authentication for specified operation paths.
// This is provided for convenience, delegating to the common helper.
func PathSkipChecker(skipPaths ...string) security.SkipChecker { // Use the common SkipChecker
	return security.PathSkipChecker(skipPaths...) // Delegate to the common helper
}
