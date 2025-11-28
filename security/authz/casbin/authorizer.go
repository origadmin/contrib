/*
 * Copyright (c) 2024 OrigAdmin. All rights reserved.
 */

package casbin

import (
	"context"
	"fmt"
	"strings" // Add this import for strings.Split

	"github.com/casbin/casbin/v2"
	"github.com/casbin/casbin/v2/model"
	"github.com/casbin/casbin/v2/persist"

	casbinv1 "github.com/origadmin/contrib/api/gen/go/security/authz/casbin/v1"
	authzv1 "github.com/origadmin/contrib/api/gen/go/security/authz/v1"
	"github.com/origadmin/contrib/security"
	"github.com/origadmin/contrib/security/authz"
	"github.com/origadmin/contrib/security/authz/casbin/adapter"
	"github.com/origadmin/runtime/interfaces/options"
	"github.com/origadmin/runtime/log"
)

const (
	DefaultWildcardItem = "*"
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
	hasDomain    bool
}

// Authorized checks if a principal is authorized to perform an action on a resource within a specific domain.
func (auth *Authorizer) Authorized(ctx context.Context, principal security.Principal, spec authz.RuleSpec) (bool, error) {
	log.Debugf("Authorizing user with principal: %+v", principal)

	var err error
	var allowed bool

	if auth.hasDomain {
		// If the model supports domains, use the domain from the spec.
		domain := spec.Domain
		if len(domain) == 0 {
			log.Debugf("Domain is empty, using wildcard item: %s", auth.wildcardItem)
			domain = auth.wildcardItem
		}
		allowed, err = auth.enforcer.Enforce(principal.GetID(), spec.Resource, spec.Action, domain)
	} else {
		// If the model does not support domains, call Enforce without the domain argument.
		// It's crucial not to pass a domain argument if the model is not configured for it.
		allowed, err = auth.enforcer.Enforce(principal.GetID(), spec.Resource, spec.Action)
	}

	if err != nil {
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
	// Ensure casbinConfig is never nil to avoid early exit and allow options/defaults to apply.
	var casbinConfig *casbinv1.Config
	if cfg != nil {
		casbinConfig = cfg.GetCasbin()
	}
	if casbinConfig == nil {
		casbinConfig = &casbinv1.Config{} // Provide an empty config if none is given
	}

	auth := &Authorizer{
		wildcardItem: DefaultWildcardItem,
	}

	// 1. Apply programmatic options (highest priority)
	configuredOptions := FromOptions(opts) // This creates an Options struct with values from 'opts'

	// Set model
	switch {
	case configuredOptions.Model != nil:
		auth.model = configuredOptions.Model
	case casbinConfig.GetModelPath() != "":
		m, err := model.NewModelFromFile(casbinConfig.GetModelPath())
		if err != nil {
			return nil, fmt.Errorf("failed to load model from config file %s: %w", casbinConfig.GetModelPath(), err)
		}
		auth.model = m
	default:
		m, err := model.NewModelFromString(DefaultModel())
		if err != nil {
			return nil, fmt.Errorf("failed to load default casbin model: %w", err)
		}
		auth.model = m
	}

	// Determine if the model has a domain.
	// A common heuristic for domain-enabled models in Casbin is the presence of a 'g' section
	// with three parameters (e.g., `g = r.sub, p.sub, r.dom`).
	// We will check the 'g' section definition in the model.
	if gAssertion, ok := auth.model["g"]["g"]; ok { // gAssertion is *model.Assertion
		// Access the Value field of the Assertion to get the string definition.
		gDef := gAssertion.Value
		// Split the definition by comma to count parameters.
		params := strings.Split(gDef, ",")
		// If there are exactly 3 parameters, we assume it's a domain-enabled model.
		if len(params) == 3 {
			auth.hasDomain = true
		}
	}

	// Set policy adapter
	if configuredOptions.Policy != nil {
		auth.policy = configuredOptions.Policy
	} else { // Apply default policy adapter
		auth.policy = adapter.NewMemory()
	}

	// Set wildcard item
	if configuredOptions.WildcardItem != "" {
		auth.wildcardItem = configuredOptions.WildcardItem
	} else { // Apply default wildcard item
		auth.wildcardItem = "*"
	}

	// Create the enforcer.
	enforcer, err := casbin.NewSyncedEnforcer(auth.model, auth.policy)
	if err != nil {
		return nil, fmt.Errorf("failed to create casbin enforcer: %w", err)
	}
	auth.enforcer = enforcer

	return auth, nil
}
