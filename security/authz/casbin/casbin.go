/*
 * Copyright (c) 2024 OrigAdmin. All rights reserved.
 */

package casbin

import (
	"github.com/casbin/casbin/v2"
	"github.com/casbin/casbin/v2/model"
	"github.com/casbin/casbin/v2/persist"
	"github.com/goexts/generic/settings"

	"github.com/origadmin/runtime/context"
	configv1 "github.com/origadmin/runtime/gen/go/config/v1"
	"github.com/origadmin/toolkits/errors"
	"github.com/origadmin/toolkits/security"
)

// Authorizer is a struct that implements the Authorizer interface.
type Authorizer struct {
	model        model.Model
	policy       persist.Adapter
	enforcer     *casbin.SyncedEnforcer
	wildcardItem string
}

func (auth *Authorizer) Authorized(ctx context.Context, claims security.UserClaims) (bool, error) {
	domain := claims.GetDomain()
	if len(domain) == 0 {
		domain = auth.wildcardItem
	}

	var err error
	var allowed bool
	if allowed, err = auth.enforcer.Enforce(claims.GetSubject(), claims.GetObject(), claims.GetAction(), domain); err != nil {
		return false, err
	} else if allowed {
		return true, nil
	}
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

func (auth *Authorizer) WithConfig(config *configv1.AuthZConfig_CasbinConfig) error {
	var err error
	if config.ModelFile != "" {
		auth.model, err = model.NewModelFromFile(config.ModelFile)
	}
	return err
}

func NewAuthorizer(cfg *configv1.Security, ss ...Setting) (security.Authorizer, error) {
	config := cfg.GetAuthz().GetCasbin()
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