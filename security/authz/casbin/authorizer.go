/* * Copyright (c) 2024 OrigAdmin. All rights reserved.
 */

package casbin

import (
	"context"
	"errors"

	"github.com/casbin/casbin/v2"
	"github.com/casbin/casbin/v2/model"
	"github.com/casbin/casbin/v2/persist"

	casbinv1 "github.com/origadmin/contrib/api/gen/go/security/authz/casbin/v1"
	authzv1 "github.com/origadmin/contrib/api/gen/go/security/authz/v1"
	"github.com/origadmin/contrib/security/authz/casbin/adapter"
	"github.com/origadmin/runtime/interfaces/options"
	"github.com/origadmin/runtime/log"

	"github.com/origadmin/contrib/security"
	"github.com/origadmin/contrib/security/authz"
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

func (auth *Authorizer) ApplyDefaults() error {
	if auth.policy == nil {
		auth.policy = adapter.NewMemory()
	}
	if auth.wildcardItem == "" {
		auth.wildcardItem = "*"
	}
	if auth.model == nil {
		auth.model, _ = model.NewModelFromString(DefaultModel())
		//if err != nil {
		//	return err
		//}
	}
	if auth.enforcer == nil {
		auth.enforcer, _ = casbin.NewSyncedEnforcer(auth.model, auth.policy)
		//if err!= nil {
		//	return err
		//}
	}
	return nil
}

func (auth *Authorizer) WithConfig(config *casbinv1.Config) error {
	var err error
	if config.GetModelPath() != "" {
		auth.model, err = model.NewModelFromFile(config.GetModelPath())
	}
	return err
}

func NewAuthorizer(cfg *authzv1.Authorizer, opts ...options.Option) (authz.Authorizer, error) {
	config := cfg.GetCasbin()
	if config == nil {
		return nil, errors.New("authorizer casbin config is empty")
	}
	var err error
	auth := &Authorizer{}
	err = auth.WithConfig(config)
	if err != nil {
		return nil, err
	}
	return auth, nil
}
