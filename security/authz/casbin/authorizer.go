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
	DefaultWildcardItem = "*"
)

var (
	fastPathNonDomainTokens = []string{"sub", "obj", "act"}
	fastPathDomainTokens    = []string{"sub", "dom", "obj", "act"}
)

func init() {
	authz.Register(authz.Casbin, authz.FactoryFunc(NewAuthorizer))
}

// preparerArgsFunc defines the function signature for preparing authorization arguments.
// It abstracts the logic for constructing the arguments for different casbin models
// (e.g., with or without domain) into a single, callable function.
type preparerArgsFunc func(principal security.Principal, spec authz.RuleSpec) []interface{}

// Authorizer is a struct that implements the Authorizer interface.
// It acts as a pure enforcement engine that trusts the incoming RuleSpec.
type Authorizer struct {
	*Options
	enforcer     *casbin.SyncedEnforcer
	hasDomain    bool
	preparerArgs preparerArgsFunc
	log          *log.Helper
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
func (auth *Authorizer) Reload() error {
	if auth.watcher != nil {
		auth.log.Info("Skip reloading casbin policy due to watcher set")
		return nil
	}
	auth.log.Info("Policy update broadcasted via watcher.")
	return auth.enforcer.LoadPolicy()
}

// GetEnforcer returns the underlying casbin enforcer.
func (auth *Authorizer) GetEnforcer() *casbin.SyncedEnforcer {
	return auth.enforcer
}

// Authorized checks if a principal is authorized by preparing the arguments and then enforcing the policy.
func (auth *Authorizer) Authorized(ctx context.Context, principal security.Principal, spec authz.RuleSpec) (bool, error) {
	args := auth.preparerArgs(principal, spec)
	auth.log.WithContext(ctx).Debugf("[AuthZ] Enforcing with args: %v", args)

	allowed, err := auth.enforcer.Enforce(args...)
	if err != nil {
		auth.log.WithContext(ctx).Errorf("[AuthZ] Enforcement failed with error: %v", err)
		return false, err
	}
	return allowed, nil
}

// initEnforcer acts as a one-time parser to determine the optimal authorization strategy
// and sets the preparerArgsFunc accordingly.
func (auth *Authorizer) initEnforcer() error {
	if auth.Options == nil {
		return fmt.Errorf("authorizer options not initialized")
	}

	enforcer, err := casbin.NewSyncedEnforcer(auth.model, auth.policy)
	if err != nil {
		return fmt.Errorf("failed to create casbin enforcer: %w", err)
	}
	auth.enforcer = enforcer

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
		auth.hasDomain = false
		auth.log.Debug("Using fast path for non-domain model.")
		auth.preparerArgs = auth.nonDomainArgs
	} else if slicesEqual(trimmedTokens, fastPathDomainTokens) {
		auth.hasDomain = true
		auth.log.Debug("Using fast path for domain model.")
		auth.preparerArgs = auth.domainArgs
	} else {
		auth.log.Debug("Using dynamic path for custom model.")
		argIndices := make([]int, 0, len(trimmedTokens))
		for _, token := range trimmedTokens {
			switch token {
			case "sub":
				argIndices = append(argIndices, 0)
			case "dom":
				argIndices = append(argIndices, 1)
				auth.hasDomain = true
			case "obj":
				argIndices = append(argIndices, 2)
			case "act":
				argIndices = append(argIndices, 3)
			default:
				return fmt.Errorf("unrecognized token '%s' in casbin model", token)
			}
		}
		auth.preparerArgs = auth.dynamicArgs(argIndices)
	}

	if auth.watcher != nil {
		if err := auth.enforcer.SetWatcher(auth.watcher); err != nil {
			return fmt.Errorf("failed to set casbin watcher: %w", err)
		}
		auth.log.Infof("Casbin watcher configured.")
	}

	return nil
}

// nonDomainArgs prepares arguments for models without domains.
func (auth *Authorizer) nonDomainArgs(principal security.Principal, spec authz.RuleSpec) []interface{} {
	return []interface{}{principal.GetID(), spec.Resource, spec.Action}
}

// domainArgs prepares arguments for models with domains.
func (auth *Authorizer) domainArgs(principal security.Principal, spec authz.RuleSpec) []interface{} {
	domain := spec.Domain
	if domain == "" {
		domain = auth.wildcardItem
	}
	return []interface{}{principal.GetID(), domain, spec.Resource, spec.Action}
}

// dynamicArgs returns an preparerArgsFunc for custom models.
func (auth *Authorizer) dynamicArgs(argIndices []int) preparerArgsFunc {
	return func(principal security.Principal, spec authz.RuleSpec) []interface{} {
		domain := spec.Domain
		if auth.hasDomain && domain == "" {
			domain = auth.wildcardItem
		}
		sourceArgs := [4]interface{}{principal.GetID(), domain, spec.Resource, spec.Action}
		args := make([]interface{}, len(argIndices))
		for i, idx := range argIndices {
			args[i] = sourceArgs[idx]
		}
		return args
	}
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
