/*
 * Copyright (c) 2024 OrigAdmin. All rights reserved.
 */

package casbin

import (
	"context"
	"fmt"

	"github.com/casbin/casbin/v2"
	"github.com/casbin/casbin/v2/model"
	"github.com/origadmin/runtime/log"
	"github.com/origadmin/runtime/interfaces/security"
)

// Enforcer implements the security.Authorizer interface for Casbin authorization.
type Enforcer struct {
	enforcer *casbin.SyncedEnforcer
	options *Options
}

// Authorize checks if the principal has permission to perform the action on the resource.
func (e *Enforcer) Authorize(ctx context.Context, p security.Principal, resourceIdentifier string, action string) (bool, error) {
	if p == nil {
		return false, fmt.Errorf("authorization failed: principal is nil")
	}

	// Get the subject (user ID)
	subject := p.GetID()
	if subject == "" {
		return false, fmt.Errorf("authorization failed: principal ID is empty")
	}

	// Get domain if domain field is configured
	domain := ""
	if e.options != nil && e.options.DomainField != "" {
		claims := p.GetClaims()
		if claims != nil {
			// Use the Get method of security.Claims
			if domainVal, ok := claims.Get(e.options.DomainField); ok {
				if domainStr, ok := domainVal.(string); ok && domainStr != "" {
					domain = domainStr
					log.Debugf("Using domain '%s' for authorization", domain)
				}
			}
		}
	}

	// Build the enforce arguments
	var args []interface{}
	if domain != "" {
		args = []interface{}{subject, domain, resourceIdentifier, action}
	} else {
		args = []interface{}{subject, resourceIdentifier, action}
	}

	// Enforce the policy
	allowed, err := e.enforcer.Enforce(args...)
	if err != nil {
		log.Errorf("Casbin enforce error: %v", err)
		return false, fmt.Errorf("authorization check failed: %w", err)
	}

	if !allowed {
		log.Debugf("Access denied: subject=%s, resource=%s, action=%s, domain=%s", 
			subject, resourceIdentifier, action, domain)
		return false, fmt.Errorf("permission denied")
	}

	log.Debugf("Access granted: subject=%s, resource=%s, action=%s, domain=%s", 
		subject, resourceIdentifier, action, domain)
	return true, nil
}

// NewCasbinAuthorizer creates a new Casbin Enforcer instance.
func NewCasbinAuthorizer(opts ...Option) (security.Authorizer, error) {
	o := FromOptions(opts...)

	// Validate required paths
	if o.ModelPath == "" {
		return nil, fmt.Errorf("model path is required for Casbin authorizer")
	}

	// Load the Casbin model
	m, err := model.NewModelFromFile(o.ModelPath)
	if err != nil {
		return nil, fmt.Errorf("failed to load Casbin model from %s: %w", o.ModelPath, err)
	}

	// Create a new enforcer
	enforcer, err := casbin.NewSyncedEnforcer(m)
	if err != nil {
		return nil, fmt.Errorf("failed to create Casbin enforcer: %w", err)
	}

	// Enable auto-save and auto-build role links
	enforcer.EnableAutoSave(true)
	enforcer.EnableAutoBuildRoleLinks(true)

	// Load policy if policy path is provided
	if o.PolicyPath != "" {
		if err := enforcer.LoadPolicy(); err != nil {
			return nil, fmt.Errorf("failed to load policy: %w", err)
		}
	}

	return &Enforcer{
		enforcer: enforcer,
		options:  o,
	}, nil
}


// Register the Casbin authorizer factory.
func Register() (string, func(...interface{}) (security.Authorizer, error)) {
	return "casbin", func(opts ...interface{}) (security.Authorizer, error) {
		var options []Option
		for _, opt := range opts {
			if o, ok := opt.(Option); ok {
				options = append(options, o)
			}
		}
		authorizer, err := NewCasbinAuthorizer(options...)
		if err != nil {
			return nil, fmt.Errorf("failed to create Casbin authorizer: %w", err)
		}
		return authorizer, nil
	}
}
