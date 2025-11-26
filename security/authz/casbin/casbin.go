/* * Copyright (c) 2024 OrigAdmin. All rights reserved. */

package casbin

import (
	"context"
	"errors"

	"github.com/casbin/casbin/v2"
	"github.com/casbin/casbin/v2/model"
	"github.com/casbin/casbin/v2/persist"
	"github.com/origadmin/runtime/log"

	"github.com/origadmin/contrib/security"
	authzFactory "github.com/origadmin/contrib/security/authz"
	securityv1 "github.com/origadmin/contrib/api/gen/go/security/v1"
)

// Authorizer is a struct that implements the Authorizer interface.
type Authorizer struct {
	model        model.Model
	policy       persist.Adapter
	enforcer     *casbin.SyncedEnforcer
	wildcardItem string
}

func (auth *Authorizer) Authorized(ctx context.Context, principal security.Principal, spec authzFactory.RuleSpec) (bool, error) {
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
		auth.policy = NewAdapter()
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

func (auth *Authorizer) WithConfig(config *securityv1.CasbinAuthorizer) error {
	var err error
	if config.ModelFile != "" {
		auth.model, err = model.NewModelFromFile(config.ModelFile)
	}
	return err
}

func NewAuthorizer(cfg *securityv1.Authorizer, ss ...Setting) (authzFactory.Authorizer, error) {
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
	return settings.ApplyErrorDefaults(auth, ss)
}