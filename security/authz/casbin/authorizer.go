/*
 * Copyright (c) 2024 OrigAdmin. All rights reserved.
 */

package casbin

import (
	"context"
	"errors"
	"fmt"

	"github.com/casbin/casbin/v2"
	"github.com/casbin/casbin/v2/model"
	"github.com/casbin/casbin/v2/persist"

	authzv1 "github.com/origadmin/contrib/api/gen/go/security/authz/v1"
	"github.com/origadmin/contrib/security"
	"github.com/origadmin/contrib/security/authz"
	"github.com/origadmin/contrib/security/authz/casbin/adapter"
	internalmodel "github.com/origadmin/contrib/security/authz/casbin/internal/model"
	"github.com/origadmin/runtime/interfaces/options"
	"github.com/origadmin/runtime/log"
)

func init() {
	authz.Register(authz.Casbin, authz.FactoryFunc(NewAuthorizer))
}

// Authorizer is a struct that implements the Authorizer interface.
type Authorizer struct {
	model        model.Model
	policy       persist.Adapter
	enforcer     *casbin.SyncedEnforcer
	wildcardItem string
}

// Authorized checks if a principal is authorized to perform an action on a resource within a specific domain.
func (auth *Authorizer) Authorized(ctx context.Context, principal security.Principal, spec authz.RuleSpec) (bool, error) {
	log.Debugf("Authorizing user with principal: %+v", principal)
	domain := spec.Domain
	if len(domain) == 0 {
		log.Debugf("Domain is empty, using wildcard item: %s", auth.wildcardItem)
		domain = auth.wildcardItem
	}

	var err error
	var allowed bool
	if allowed, err = auth.enforcer.Enforce(principal.GetID(), spec.Resource, spec.Action, domain); err != nil {
		log.Errorf("Authorization failed with error: %v", err)
		return false, err
	} else if allowed {
		log.Debugf("Authorization successful for user with principal: %+v", principal)
		return true, nil
	}
	log.Debugf("Authorization failed for user with principal: %+v", principal)
	return false, nil
}

// NewAuthorizer creates a new Authorizer instance.
// It initializes the authorizer based on the provided configuration and options.
// The initialization follows a clear priority:
// 1. Programmatic options (`opts`) are applied first.
// 2. If not set by options, settings from the configuration file (`cfg`) are used.
// 3. If still not set, sensible defaults are applied (e.g., in-memory adapter, default model).
func NewAuthorizer(cfg *authzv1.Authorizer, opts ...options.Option) (authz.Authorizer, error) {
	config := cfg.GetCasbin()
	if config == nil {
		return nil, errors.New("authorizer casbin config is empty")
	}

	auth := &Authorizer{
		wildcardItem: "*", // Set a default wildcard item.
	}

	// Create an AuthorizerContext to apply options.
	o := FromOptions(opts)

	// If a model path is provided in the config and no model has been set by options, load it.
	if o.model == nil && config.GetModelPath() != "" {
		m, err := model.NewModelFromFile(config.GetModelPath())
		if err != nil {
			return nil, fmt.Errorf("failed to load model from file %s: %w", config.GetModelPath(), err)
		}
		o.model = m
	}

	// If no model is configured (neither by options nor by config), use the default model.
	if o.model == nil {
		m, err := model.NewModelFromString(internalmodel.DefaultRestfullWithRoleModel)
		if err != nil {
			// This should not happen with the default model, but it's good practice to handle it.
			return nil, fmt.Errorf("failed to load default casbin model: %w", err)
		}
		o.model = m
	}

	// If no policy adapter is configured, use the default in-memory adapter.
	if o.policy == nil {
		o.policy = adapter.NewMemory()
	}

	// Create the enforcer.
	enforcer, err := casbin.NewSyncedEnforcer(o.model, o.policy)
	if err != nil {
		return nil, fmt.Errorf("failed to create casbin enforcer: %w", err)
	}
	auth.enforcer = enforcer

	return auth, nil
}
