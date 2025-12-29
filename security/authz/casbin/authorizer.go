/*
 * Copyright (c) 2024 OrigAdmin. All rights reserved.
 */

package casbin

import (
	"context"
	"fmt"
	"strings"

	"github.com/casbin/casbin/v2"
	"github.com/casbin/casbin/v2/model"

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

	// authMode determines the authorization strategy.
	authModeFastPathNonDomain = 0 // Fast path for "sub, obj, act"
	authModeFastPathDomain    = 1 // Fast path for "sub, dom, obj, act"
	authModeDynamic           = 2 // Fallback for custom models
)

var (
	// Pre-defined token sequences for fast path detection.
	fastPathNonDomainTokens = []string{"sub", "obj", "act"}
	fastPathDomainTokens    = []string{"sub", "dom", "obj", "act"}
)

func init() {
	authz.Register(authz.Casbin, authz.FactoryFunc(newAuthorizer))
}

// Authorizer is a struct that implements the Authorizer interface.
type Authorizer struct {
	*Options // Embed a pointer to Options

	// Internal state
	enforcer   *casbin.SyncedEnforcer
	hasDomain  bool
	authMode   int   // The authorization mode (fast path or dynamic).
	argIndices []int // Stores the mapping for the dynamic mode.
	log        *log.Helper
}

func newAuthorizer(cfg *authzv1.Authorizer, opts ...Option) (authz.Authorizer, error) {
	return NewAuthorizer(cfg, opts...)
}

// NewAuthorizer creates a new Authorizer instance.
func NewAuthorizer(cfg *authzv1.Authorizer, opts ...Option) (*Authorizer, error) {
	finalOpts, err := newWithOptions(cfg, opts...)
	if err != nil {
		return nil, err
	}

	logger := log.FromOptions(opts)
	helper := log.NewHelper(log.With(logger, "module", "security.authz.casbin"))

	auth := &Authorizer{
		Options: finalOpts,
		log:     helper,
	}

	if err := auth.initEnforcer(); err != nil {
		return nil, err
	}

	return auth, nil
}

// newWithOptions merges configurations from all sources.
func newWithOptions(cfg *authzv1.Authorizer, opts ...options.Option) (*Options, error) {
	finalOpts := FromOptions(opts...)

	if cfg != nil {
		var casbinConfig *casbinv1.Config
		if cfg.GetCasbin() != nil {
			casbinConfig = cfg.GetCasbin()
		}

		if casbinConfig != nil {
			if finalOpts.model == nil {
				if casbinConfig.GetModelPath() != "" {
					m, err := model.NewModelFromFile(casbinConfig.GetModelPath())
					if err != nil {
						return nil, fmt.Errorf("failed to load model from config file %s: %w", casbinConfig.GetModelPath(), err)
					}
					finalOpts.model = m
				} else if casbinConfig.GetModel() != "" {
					m, err := model.NewModelFromString(casbinConfig.GetModel())
					if err != nil {
						return nil, fmt.Errorf("failed to load embedded model content: %w", err)
					}
					finalOpts.model = m
				}
			}
			if finalOpts.wildcardItem == "" && casbinConfig.GetWildcardItem() != "" {
				finalOpts.wildcardItem = casbinConfig.GetWildcardItem()
			}
			if finalOpts.policy == nil {
				if casbinConfig.GetPolicyPath() != "" {
					finalOpts.policy = adapter.NewFile(casbinConfig.GetPolicyPath())
				} else if len(casbinConfig.GetEmbeddedPolicies()) > 0 {
					policies := make(map[string][][]string)
					for _, p := range casbinConfig.GetEmbeddedPolicies() {
						if p.GetPType() == "" || len(p.GetRule()) == 0 {
							return nil, fmt.Errorf("embedded policy rule is incomplete")
						}
						policies[p.GetPType()] = append(policies[p.GetPType()], p.GetRule())
					}
					finalOpts.policy = adapter.NewWithPolicies(policies)
				}
			}
		}
	}

	if finalOpts.model == nil {
		m, err := model.NewModelFromString(DefaultModel())
		if err != nil {
			return nil, fmt.Errorf("failed to load default casbin model: %w", err)
		}
		finalOpts.model = m
	}
	if finalOpts.policy == nil {
		// If no policy is configured via options, config file, or embedded policies,
		// default to an empty in-memory adapter. This implements a "default deny"
		// security posture, meaning no authorization rules are present until explicitly
		// added or loaded from a source.
		finalOpts.policy = adapter.NewMemory()
	}
	if finalOpts.wildcardItem == "" {
		finalOpts.wildcardItem = DefaultWildcardItem
	}

	return finalOpts, nil
}

// Authorized checks if a principal is authorized. It uses a fast path for standard models
// and a dynamic path for custom models, ensuring both performance and flexibility.
func (auth *Authorizer) Authorized(ctx context.Context, principal security.Principal, spec authz.RuleSpec) (bool, error) {
	auth.log.Debugf("Authorizing user with principal: %+v", principal)

	var allowed bool
	var err error

	switch auth.authMode {
	case authModeFastPathNonDomain:
		// Highest performance path for the most common non-domain model.
		auth.log.Debugf("Casbin Enforce args: sub=%s, obj=%s, act=%s", principal.GetID(), spec.Resource, spec.Action)
		allowed, err = auth.enforcer.Enforce(principal.GetID(), spec.Resource, spec.Action)

	case authModeFastPathDomain:
		// Highest performance path for the most common domain model.
		domain := spec.Domain
		if len(domain) == 0 {
			domain = auth.wildcardItem
		}
		auth.log.Debugf("Casbin Enforce args: sub=%s, dom=%s, obj=%s, act=%s", principal.GetID(), domain, spec.Resource, spec.Action)
		allowed, err = auth.enforcer.Enforce(principal.GetID(), domain, spec.Resource, spec.Action)

	case authModeDynamic:
		// Flexible path for any custom model definition.
		domain := spec.Domain
		if auth.hasDomain && len(domain) == 0 {
			domain = auth.wildcardItem
		}
		sourceArgs := [4]interface{}{principal.GetID(), domain, spec.Resource, spec.Action}
		args := make([]interface{}, len(auth.argIndices))
		for i, idx := range auth.argIndices {
			args[i] = sourceArgs[idx]
		}
		auth.log.Debugf("Casbin Enforce args: %v", args)
		allowed, err = auth.enforcer.Enforce(args...)

	default:
		// This case should ideally never be reached.
		return false, fmt.Errorf("internal error: invalid authorization mode")
	}

	if err != nil {
		auth.log.Errorf("Authorization failed with error: %v", err)
		return false, err
	}

	if allowed {
		auth.log.Debugf("Authorization successful for user with principal: %+v", principal)
		return true, nil
	}

	auth.log.Debugf("Authorization failed for user with principal: %+v", principal)
	return false, nil
}

// initEnforcer acts as a one-time parser to determine the optimal authorization strategy.
func (auth *Authorizer) initEnforcer() error {
	if auth.Options == nil {
		return fmt.Errorf("authorizer options not initialized")
	}

	enforcer, err := casbin.NewSyncedEnforcer(auth.model, auth.policy)
	if err != nil {
		return fmt.Errorf("failed to create casbin enforcer: %w", err)
	}
	auth.enforcer = enforcer

	auth.authMode = authModeDynamic

	r, ok := auth.model["r"]
	if !ok {
		return fmt.Errorf("casbin model is missing request_definition section")
	}
	rdef, ok := r["r"]
	if !ok {
		return fmt.Errorf("casbin model is missing request_definition 'r'")
	}

	tokens := strings.Split(rdef.Value, ",")
	trimmedTokens := make([]string, 0, len(tokens))
	for _, token := range tokens {
		trimmedTokens = append(trimmedTokens, strings.TrimSpace(token))
	}

	if slicesEqual(trimmedTokens, fastPathNonDomainTokens) {
		auth.authMode = authModeFastPathNonDomain
		auth.hasDomain = false
		auth.log.Debug("Using fast path for non-domain model.")
	} else if slicesEqual(trimmedTokens, fastPathDomainTokens) {
		auth.authMode = authModeFastPathDomain
		auth.hasDomain = true
		auth.log.Debug("Using fast path for domain model.")
	} else {
		auth.log.Debug("Using dynamic path for custom model.")
		auth.argIndices = make([]int, 0, len(trimmedTokens))
		for _, token := range trimmedTokens {
			switch token {
			case "sub":
				auth.argIndices = append(auth.argIndices, 0)
			case "dom":
				auth.argIndices = append(auth.argIndices, 1)
				auth.hasDomain = true
			case "obj":
				auth.argIndices = append(auth.argIndices, 2)
			case "act":
				auth.argIndices = append(auth.argIndices, 3)
			default:
				return fmt.Errorf("unrecognized token '%s' in casbin model", token)
			}
		}
	}

	if auth.watcher != nil {
		if err := auth.enforcer.SetWatcher(auth.watcher); err != nil {
			return fmt.Errorf("failed to set casbin watcher: %w", err)
		}
		auth.log.Infof("Casbin watcher configured.")
	}

	return nil
}

// slicesEqual performs a manual, efficient comparison of two string slices.
func slicesEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
