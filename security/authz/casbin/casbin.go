/*
 * Copyright (c) 2024 OrigAdmin. All rights reserved.
 */

package casbin

import (
	"context"

	"github.com/casbin/casbin/v2/model"

	securityv1 "github.com/origadmin/contrib/api/gen/go/security/v1"
	"github.com/origadmin/contrib/security"
	"github.com/origadmin/contrib/security/authz"
	"github.com/origadmin/runtime/interfaces/options"
	"github.com/origadmin/runtime/log"
)

const (
	// Name is the name of the casbin authorizer provider.
	Name = "casbin"
)

// blueprint implements the authz.Blueprint interface.
type blueprint struct{}

// NewProvider creates a new casbin Provider.
func (b *blueprint) NewProvider(cfg *securityv1.Security, opts ...options.Option) (authz.Provider, error) {
	casbinCfg := cfg.GetAuthz().GetCasbin()
	if casbinCfg == nil {
		return nil, securityv1.ErrorAuthorizerConfigInvalid("casbin configuration is missing")
	}

	o := FromOptions(opts...)
	if err := o.Apply(casbinCfg); err != nil {
		return nil, err
	}

	m, err := model.NewModelFromString(o.model)
	if err != nil {
		return nil, securityv1.ErrorAuthorizerConfigInvalid("invalid casbin model: %v", err)
	}

	enforcer, err := casbin.NewSyncedEnforcer(m, o.adapter)
	if err != nil {
		return nil, securityv1.ErrorAuthorizerFailed("failed to create casbin enforcer: %v", err)
	}

	if o.watcher != nil {
		if err := enforcer.SetWatcher(o.watcher); err != nil {
			return nil, securityv1.ErrorAuthorizerFailed("failed to set casbin watcher: %v", err)
		}
	}

	authorizer := &Authorizer{
		enforcer:     enforcer,
		wildcardItem: o.wildcardItem,
	}

	return newProvider(authorizer), nil
}

func init() {
	authz.Register(Name, &blueprint{})
}

// provider implements the authz.Provider interface for the casbin component.
type provider struct {
	auth *Authorizer
}

// newProvider creates a new casbin provider.
func newProvider(auth *Authorizer) authz.Provider {
	return &provider{auth: auth}
}

// Authorizer returns the Authorizer capability.
func (p *provider) Authorizer() (authz.Authorizer, bool) {
	return p.auth, true
}

// Querier returns the PermissionQuerier capability.
func (p *provider) Querier() (authz.PermissionQuerier, bool) {
	return p.auth, true
}

// Authorizer is a struct that implements the authz.Authorizer and authz.PermissionQuerier interfaces using casbin.
type Authorizer struct {
	enforcer     *casbin.SyncedEnforcer
	wildcardItem string
}

// Authorized checks if the principal is authorized based on the provided rule specification.
//
// Note: RuleSpec.Attributes are provided for ABAC (Attribute-Based Access Control) support.
// However, their actual use in Casbin's authorization decision depends entirely on the
// configuration of the loaded Casbin model (e.g., the 'matchers' section in the .conf file).
// If the Casbin model is not configured to use attributes, they will be ignored by Casbin's Enforce method.
// If attributes are present in spec.Attributes but the model doesn't use them, a warning will be logged.
func (a *Authorizer) Authorized(ctx context.Context, p security.Principal, spec authz.RuleSpec) (bool, error) {
	subject := p.GetID()
	domain := spec.Domain
	if domain == "" {
		domain = a.wildcardItem
	}

	// Prepare arguments for Casbin Enforce.
	// We pass the core (subject, domain, resource, action) arguments.
	// If the Casbin model is configured for ABAC, it would expect additional arguments for attributes.
	// For simplicity and to avoid implicit model assumptions, we only pass the core arguments here.
	// If spec.Attributes are present, a warning is logged to indicate they might not be used by the current model.
	args := []interface{}{subject, domain, spec.Resource, spec.Action}

	if spec.Attributes != nil {
		log.Warnf("RuleSpec.Attributes are present but not explicitly passed to Casbin's Enforce method with the default argument structure. Ensure your Casbin model is configured for ABAC if you intend to use them. Attributes: %v", spec.Attributes)
	}

	log.Debugf("Authorizing: Subject=%s, Domain=%s, Resource=%s, Action=%s, Attributes=%v", subject, domain, spec.Resource, spec.Action, spec.Attributes)

	allowed, err := a.enforcer.Enforce(args...)
	if err != nil {
		log.Errorf("Casbin authorization failed with error: %v", err)
		return false, securityv1.ErrorAuthorizerFailed("casbin enforce error: %v", err)
	}

	if !allowed {
		log.Debugf("Authorization denied for: Subject=%s, Domain=%s, Resource=%s, Action=%s, Attributes=%v", subject, domain, spec.Resource, spec.Action, spec.Attributes)
		return false, nil // Returning (false, nil) indicates a successful check that resulted in "denied".
	}

	log.Debugf("Authorization successful for: Subject=%s, Domain=%s, Resource=%s, Action=%s, Attributes=%v", subject, domain, spec.Resource, spec.Action, spec.Attributes)
	return true, nil
}

// FilterAuthorized filters a list of rule specifications and returns the subset that the principal is authorized to perform.
//
// Note: RuleSpec.Attributes are provided for ABAC support. Their actual use depends on the Casbin model configuration.
// If attributes are present but the model doesn't use them, a warning will be logged.
func (a *Authorizer) FilterAuthorized(ctx context.Context, p security.Principal, specs []authz.RuleSpec) ([]authz.RuleSpec, error) {
	if len(specs) == 0 {
		return nil, nil
	}

	subject := p.GetID()
	requests := make([][]interface{}, len(specs))
	for i, spec := range specs {
		domain := spec.Domain
		if domain == "" {
			domain = a.wildcardItem
		}

		// Similar to Authorized, we only pass the core arguments to BatchEnforce.
		// Attributes are not explicitly passed here to avoid implicit model assumptions.
		currentArgs := []interface{}{subject, domain, spec.Resource, spec.Action}

		if spec.Attributes != nil {
			log.Warnf("RuleSpec.Attributes are present in batch authorization but not explicitly passed to Casbin's BatchEnforce method with the default argument structure. Ensure your Casbin model is configured for ABAC if you intend to use them. Attributes: %v", spec.Attributes)
		}
		requests[i] = currentArgs
	}

	results, err := a.enforcer.BatchEnforce(requests)
	if err != nil {
		log.Errorf("Casbin batch authorization failed with error: %v", err)
		return nil, securityv1.ErrorAuthorizerFailed("casbin batch enforce error: %v", err)
	}

	allowedSpecs := make([]authz.RuleSpec, 0, len(specs))
	for i, allowed := range results {
		if allowed {
			allowedSpecs = append(allowedSpecs, specs[i])
		}
	}

	return allowedSpecs, nil
}

// FilterAuthorizedResources filters a given list of resources, returning the resources the Principal is authorized to access.
//
// Note: specTemplate.Attributes are provided for ABAC support. Their actual use depends on the Casbin model configuration.
// If attributes are present but the model doesn't use them, a warning will be logged.
func (a *Authorizer) FilterAuthorizedResources(ctx context.Context, p security.Principal, specTemplate authz.RuleSpec, resources []string) ([]string, error) {
	if len(resources) == 0 {
		return nil, nil
	}

	subject := p.GetID()
	requests := make([][]interface{}, len(resources))
	for i, res := range resources {
		domain := specTemplate.Domain
		if domain == "" {
			domain = a.wildcardItem
		}

		currentArgs := []interface{}{subject, domain, res, specTemplate.Action} // Use res for resource

		if specTemplate.Attributes != nil {
			log.Warnf("specTemplate.Attributes are present in resource filter but not explicitly passed to Casbin's BatchEnforce method with the default argument structure. Ensure your Casbin model is configured for ABAC if you intend to use them. Attributes: %v", specTemplate.Attributes)
		}
		requests[i] = currentArgs
	}

	results, err := a.enforcer.BatchEnforce(requests)
	if err != nil {
		log.Errorf("Casbin batch authorization failed for resources with error: %v", err)
		return nil, securityv1.ErrorAuthorizerFailed("casbin batch enforce for resources error: %v", err)
	}

	allowedResources := make([]string, 0, len(resources))
	for i, allowed := range results {
		if allowed {
			allowedResources = append(allowedResources, resources[i])
		}
	}

	return allowedResources, nil
}

// FilterAuthorizedActions filters a given list of actions, returning the actions the Principal is authorized to perform.
//
// Note: specTemplate.Attributes are provided for ABAC support. Their actual use depends on the Casbin model configuration.
// If attributes are present but the model doesn't use them, a warning will be logged.
func (a *Authorizer) FilterAuthorizedActions(ctx context.Context, p security.Principal, specTemplate authz.RuleSpec, actions []string) ([]string, error) {
	if len(actions) == 0 {
		return nil, nil
	}

	subject := p.GetID()
	requests := make([][]interface{}, len(actions))
	for i, act := range actions {
		domain := specTemplate.Domain
		if domain == "" {
			domain = a.wildcardItem
		}

		currentArgs := []interface{}{subject, domain, specTemplate.Resource, act} // Use act for action

		if specTemplate.Attributes != nil {
			log.Warnf("specTemplate.Attributes are present in action filter but not explicitly passed to Casbin's BatchEnforce method with the default argument structure. Ensure your Casbin model is configured for ABAC if you intend to use them. Attributes: %v", specTemplate.Attributes)
		}
		requests[i] = currentArgs
	}

	results, err := a.enforcer.BatchEnforce(requests)
	if err != nil {
		log.Errorf("Casbin batch authorization failed for actions with error: %v", err)
		return nil, securityv1.ErrorAuthorizerFailed("casbin batch enforce for actions error: %v", err)
	}

	allowedActions := make([]string, 0, len(actions))
	for i, allowed := range results {
		if allowed {
			allowedActions = append(allowedActions, actions[i])
		}
	}

	return allowedActions, nil
}

// FilterAuthorizedDomains filters a given list of domains, returning the domains the Principal is authorized to access.
//
// Note: specTemplate.Attributes are provided for ABAC support. Their actual use depends on the Casbin model configuration.
// If attributes are present but the model doesn't use them, a warning will be logged.
func (a *Authorizer) FilterAuthorizedDomains(ctx context.Context, p security.Principal, specTemplate authz.RuleSpec, domains []string) ([]string, error) {
	if len(domains) == 0 {
		return nil, nil
	}

	subject := p.GetID()
	requests := make([][]interface{}, len(domains))
	for i, dom := range domains {
		currentArgs := []interface{}{subject, dom, specTemplate.Resource, specTemplate.Action} // Use dom for domain

		if specTemplate.Attributes != nil {
			log.Warnf("specTemplate.Attributes are present in domain filter but not explicitly passed to Casbin's BatchEnforce method with the default argument structure. Ensure your Casbin model is configured for ABAC if you intend to use them. Attributes: %v", specTemplate.Attributes)
		}
		requests[i] = currentArgs
	}

	results, err := a.enforcer.BatchEnforce(requests)
	if err != nil {
		log.Errorf("Casbin batch authorization failed for domains with error: %v", err)
		return nil, securityv1.ErrorAuthorizerFailed("casbin batch enforce for domains error: %v", err)
	}

	allowedDomains := make([]string, 0, len(domains))
	for i, allowed := range results {
		if allowed {
			allowedDomains = append(allowedDomains, domains[i])
		}
	}

	return allowedDomains, nil
}

// Interface compliance checks.
var (
	_ authz.Authorizer        = (*Authorizer)(nil)
	_ authz.PermissionQuerier = (*Authorizer)(nil)
)
