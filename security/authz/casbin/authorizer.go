/*
 * Copyright (c) 2024 OrigAdmin. All rights reserved.
 */

package casbin

import (
	"context"
	"fmt"
	"strings"

	"github.com/casbin/casbin/v3"
	"github.com/casbin/casbin/v3/model"

	casbinv1 "github.com/origadmin/contrib/api/gen/go/security/authz/casbin/v1"
	authzv1 "github.com/origadmin/contrib/api/gen/go/security/authz/v1"
	"github.com/origadmin/contrib/security"
	"github.com/origadmin/contrib/security/authz"
	"github.com/origadmin/contrib/security/authz/casbin/adapter"
	"github.com/origadmin/runtime/interfaces/options"
	"github.com/origadmin/runtime/log"
)

const (
	DefaultWildcardItem       = "*"
	authModeFastPathNonDomain = 0
	authModeFastPathDomain    = 1
	authModeDynamic           = 2
)

var (
	fastPathNonDomainTokens = []string{"sub", "obj", "act"}
	fastPathDomainTokens    = []string{"sub", "dom", "obj", "act"}
)

func init() {
	authz.Register(authz.Casbin, authz.FactoryFunc(NewAuthorizer))
}

// Authorizer is a struct that implements the Authorizer interface.
// It also implements the authz.Reloader interface to support dynamic policy updates.
type Authorizer struct {
	*Options
	enforcer   *casbin.SyncedEnforcer
	hasDomain  bool
	authMode   int
	argIndices []int
	log        *log.Helper
}

// NewOptions creates a new Options object from the given configuration and functional options.
func NewOptions(cfg *authzv1.Authorizer, opts ...Option) (*Options, error) {
	return newWithOptions(cfg, opts...)
}

// New creates a new Authorizer instance from a pre-built Options object and a logger.
func New(opts *Options, logger log.Logger) (*Authorizer, error) {
	helper := log.NewHelper(log.With(logger, "module", "security.authz.casbin"))

	auth := &Authorizer{
		Options: opts,
		log:     helper,
	}

	if err := auth.initEnforcer(); err != nil {
		return nil, err
	}

	return auth, nil
}

// NewAuthorizer creates a new Authorizer instance.
func NewAuthorizer(cfg *authzv1.Authorizer, opts ...Option) (authz.Authorizer, error) {
	finalOpts, err := newWithOptions(cfg, opts...)
	if err != nil {
		return nil, err
	}

	return New(finalOpts, finalOpts.Logger)
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
		finalOpts.policy = adapter.NewMemory()
	}
	if finalOpts.wildcardItem == "" {
		finalOpts.wildcardItem = DefaultWildcardItem
	}

	return finalOpts, nil
}

// Reload implements the authz.Reloader interface.
// It triggers the watcher to broadcast a policy change notification.
// It is the responsibility of the watcher's subscribers to then reload their policies.
func (auth *Authorizer) Reload() error {
	if auth.watcher == nil {
		auth.log.Warn("Casbin watcher is not configured, policy reload notification will not be sent.")
		// In a single-node setup, we might want to force a local reload.
		// However, in a distributed setup, this could lead to inconsistencies
		// if other nodes don't reload. The correct approach is to ensure a watcher is configured.
		return auth.enforcer.LoadPolicy() // Fallback to local load if no watcher
	}

	// Trigger the watcher to notify all instances (including this one) to reload the policy.
	// The actual reload is handled by the callback set within the watcher implementation.
	if err := auth.watcher.Update(); err != nil {
		auth.log.Errorf("Failed to broadcast policy update via watcher: %v", err)
		return err
	}
	auth.log.Info("Policy update broadcasted via watcher.")

	return nil
}

// Authorized checks if a principal is authorized.
func (auth *Authorizer) Authorized(ctx context.Context, principal security.Principal, spec authz.RuleSpec) (bool, error) {
	var allowed bool
	var err error

	switch auth.authMode {
	case authModeFastPathNonDomain:
		args := []interface{}{principal.GetID(), spec.Resource, spec.Action}
		auth.log.WithContext(ctx).Debugf("[AuthZ] Enforcing with: sub=%v, obj=%v, act=%v", args...)
		allowed, err = auth.enforcer.Enforce(args...)

	case authModeFastPathDomain:
		domain := spec.Domain
		if len(domain) == 0 {
			domain = auth.wildcardItem
		}
		args := []interface{}{principal.GetID(), domain, spec.Resource, spec.Action}
		auth.log.WithContext(ctx).Debugf("[AuthZ] Enforcing with: sub=%v, dom=%v, obj=%v, act=%v", args...)
		allowed, err = auth.enforcer.Enforce(args...)

	case authModeDynamic:
		domain := spec.Domain
		if auth.hasDomain && len(domain) == 0 {
			domain = auth.wildcardItem
		}
		sourceArgs := [4]interface{}{principal.GetID(), domain, spec.Resource, spec.Action}
		args := make([]interface{}, len(auth.argIndices))
		for i, idx := range auth.argIndices {
			args[i] = sourceArgs[idx]
		}
		auth.log.WithContext(ctx).Debugf("[AuthZ] Enforcing with dynamic args: %v", args)
		allowed, err = auth.enforcer.Enforce(args...)

	default:
		return false, fmt.Errorf("internal error: invalid authorization mode")
	}

	if err != nil {
		auth.log.WithContext(ctx).Errorf("[AuthZ] Enforcement failed with error: %v", err)
		return false, err
	}

	// No log on failure, as the middleware already logs the denial.
	return allowed, nil
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
