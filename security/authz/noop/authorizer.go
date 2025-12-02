/* * Copyright (c) 2024 OrigAdmin. All rights reserved. */

package casbin

import (
	"context"

	"github.com/origadmin/runtime/interfaces/options"

	authzv1 "github.com/origadmin/contrib/api/gen/go/security/authz/v1"
	"github.com/origadmin/contrib/security"
	"github.com/origadmin/contrib/security/authz"
)

func init() {
	authz.Register(authz.Noop, authz.FactoryFunc(NewAuthorizer))
}

// authorizer is a struct that implements the authorizer interface.
type authorizer struct{}

func (auth *authorizer) Authorized(ctx context.Context, principal security.Principal, spec authz.RuleSpec) (bool, error) {
	return false, nil
}

func NewAuthorizer(cfg *authzv1.Authorizer, opts ...options.Option) (authz.Authorizer, error) {
	return &authorizer{}, nil
}
