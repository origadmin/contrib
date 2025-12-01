package middleware

import (
	"github.com/origadmin/runtime/interfaces/options"
	"github.com/origadmin/runtime/middleware" // Import the runtime middleware package for Chain

	"github.com/origadmin/contrib/security" // Import security for SkipChecker
	"github.com/origadmin/contrib/security/authn"
	"github.com/origadmin/contrib/security/authz"
	authnMw "github.com/origadmin/contrib/security/middleware/authn"
	authzMw "github.com/origadmin/contrib/security/middleware/authz"
	propagationMw "github.com/origadmin/contrib/security/middleware/propagation" // Import propagation package
	"github.com/origadmin/contrib/security/principal"
)

// Factory creates a consistent set of security middleware.
// It ensures that all created client and server middleware use the same principal propagation type.
type Factory struct {
	propType principal.PropagationType
}

// NewFactory creates a new middleware factory.
// The propType determines which protocol (e.g., Kratos, GRPC, HTTP) is used to propagate principals.
func NewFactory(propType principal.PropagationType) *Factory {
	return &Factory{
		propType: propType,
	}
}

// NewGateway creates a server-side middleware for services that act as a gateway.
// It performs authentication and then propagates the resulting principal.
// It does not perform authorization.
func (f *Factory) NewGateway(authenticator authn.Authenticator, skipChecker security.SkipChecker) middleware.KMiddleware {
	authnOpts := []options.Option{authnMw.WithSkipChecker(skipChecker)}
	authnMW := authnMw.New(authenticator, authnOpts...)
	// Gateway mode authenticates and then implicitly relies on the transport to propagate.
	return authnMW.Server()
}

// NewBackend creates a server-side middleware for backend services.
// It expects a principal to be propagated in the context (using the factory's propagation type)
// and performs authorization based on it.
func (f *Factory) NewBackend(authorizer authz.Authorizer, skipChecker security.SkipChecker) middleware.KMiddleware {
	authzOpts := []options.Option{authzMw.WithSkipChecker(skipChecker)}
	propagationOpts := []options.Option{propagationMw.WithPropagationType(f.propType)}

	authzMW := authzMw.New(authorizer, authzOpts...)
	propagationMW := propagationMw.New(propagationOpts...)

	// Backend chain: first, ensure principal is propagated, then authorize.
	return middleware.KChain(propagationMW.Server(), authzMW.Server())
}

// NewStandalone creates a server-side middleware for services that perform both authentication and authorization.
func (f *Factory) NewStandalone(authenticator authn.Authenticator, authorizer authz.Authorizer, authnSkip security.SkipChecker, authzSkip security.SkipChecker) middleware.KMiddleware {
	authnOpts := []options.Option{authnMw.WithSkipChecker(authnSkip)}
	authzOpts := []options.Option{authzMw.WithSkipChecker(authzSkip)}

	authnMW := authnMw.New(authenticator, authnOpts...)
	authzMW := authzMw.New(authorizer, authzOpts...)

	// Standalone chain: first authenticate, then authorize.
	return middleware.KChain(authnMW.Server(), authzMW.Server())
}

// NewClient creates the client-side security middleware.
// It uses the factory's propagation type to propagate the principal from the context to the outgoing request.
func (f *Factory) NewClient() middleware.KMiddleware {
	propagationOpts := []options.Option{propagationMw.WithPropagationType(f.propType)}
	propagationMW := propagationMw.New(propagationOpts...)
	return propagationMW.Client()
}
