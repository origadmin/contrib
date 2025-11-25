/*
 * Copyright (c) 2024 OrigAdmin. All rights reserved.
 */

// Package runtime provides the bridge for security middleware to the runtime framework.
package runtime

import (
	"fmt"

	authzv1 "github.com/origadmin/contrib/api/gen/go/security/authz/v1"
	authzFactory "github.com/origadmin/contrib/security/authz"
	authzMiddleware "github.com/origadmin/contrib/security/middleware/authz"
	middlewarev1 "github.com/origadmin/runtime/api/gen/go/config/middleware/v1"
	"github.com/origadmin/runtime/log"
	runtimeMiddleware "github.com/origadmin/runtime/middleware" // Alias to avoid conflict with this package name
)

// securityFactory is a factory for creating security middleware.
type securityFactory struct{}

// NewMiddlewareClient creates a new client-side security middleware.
// Security middleware is typically server-side, so this returns nil.
func (f *securityFactory) NewMiddlewareClient(cfg *middlewarev1.Middleware, opts ...runtimeMiddleware.Option) (runtimeMiddleware.KMiddleware, bool) {
	return nil, false
}

// NewMiddlewareServer creates a new server-side security middleware.
func (f *securityFactory) NewMiddlewareServer(cfg *middlewarev1.Middleware, opts ...runtimeMiddleware.Option) (runtimeMiddleware.KMiddleware, bool) {
	if cfg.GetSecurity() == nil {
		log.Warnf("security middleware configuration is missing")
		return nil, false
	}

	// TODO: Implement actual authz.Provider creation based on configuration.
	// For now, we'll use a dummy provider.
	provider := &dummyAuthzProvider{
		defaultPolicy: cfg.GetSecurity().GetDefaultPolicy(),
	}

	return authzMiddleware.NewAuthZMiddleware(provider, opts...).Server(), true
}

// dummyAuthzProvider is a placeholder for authzFactory.Provider.
// In a real scenario, this would be initialized based on the security configuration.
type dummyAuthzProvider struct {
	defaultPolicy string
}

// Authorizer returns an Authorizer instance.
func (d *dummyAuthzProvider) Authorizer() (authzFactory.Authorizer, bool) {
	// For demonstration, we'll return a simple authorizer.
	return &dummyAuthorizer{defaultPolicy: d.defaultPolicy}, true
}

// Authenticator returns an Authenticator instance.
func (d *dummyAuthzProvider) Authenticator() (authzFactory.Authenticator, bool) {
	return nil, false // Not implemented for authz middleware
}

// dummyAuthorizer is a placeholder for authzFactory.Authorizer.
type dummyAuthorizer struct {
	defaultPolicy string
}

// Authorize performs an authorization check.
func (d *dummyAuthorizer) Authorize(ctx authzv1.Context, principal authzFactory.Principal, resource, action string) (bool, error) {
	// Simple authorization logic for demonstration.
	// In a real application, this would involve checking roles, permissions, etc.
	if d.defaultPolicy == "allow" {
		log.Infof("dummyAuthorizer: allowing access for principal %s to resource %s, action %s", principal.GetID(), resource, action)
		return true, nil
	}
	log.Warnf("dummyAuthorizer: denying access for principal %s to resource %s, action %s (default policy: %s)", principal.GetID(), resource, action, d.defaultPolicy)
	return false, fmt.Errorf("access denied by default policy: %s", d.defaultPolicy)
}

func init() {
	// Register the security middleware factory with the runtime middleware builder.
	// The name "security" is used to identify this middleware in configuration.
	runtimeMiddleware.RegisterFactory(runtimeMiddleware.Name("security"), &securityFactory{})
}
