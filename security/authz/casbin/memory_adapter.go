/*
 * Copyright (c) 2024 OrigAdmin. All rights reserved.
 */

package casbin

import (
	"github.com/casbin/casbin/v2/model"
	"github.com/casbin/casbin/v2/persist"
)

// memoryAdapter is an in-memory adapter for Casbin.
// It's useful for testing or for scenarios where policies are not persisted.
type memoryAdapter struct {
	policies map[string][][]string
}

// NewMemoryAdapter creates a new in-memory adapter.
func NewMemoryAdapter() persist.Adapter {
	return &memoryAdapter{
		policies: make(map[string][][]string),
	}
}

// LoadPolicy loads all policy rules from the storage.
func (a *memoryAdapter) LoadPolicy(m model.Model) error {
	for ptype, rules := range a.policies {
		for _, rule := range rules {
			err := persist.LoadPolicyLine(ptype+", "+rule[0], m)
			if err != nil {
				return err
			}
		}
	}
	return nil
}

// SavePolicy saves all policy rules to the storage.
func (a *memoryAdapter) SavePolicy(m model.Model) error {
	a.policies = make(map[string][][]string)
	for ptype, ast := range m["p"] {
		for _, rule := range ast.Policy {
			a.policies[ptype] = append(a.policies[ptype], rule)
		}
	}
	for ptype, ast := range m["g"] {
		for _, rule := range ast.Policy {
			a.policies[ptype] = append(a.policies[ptype], rule)
		}
	}
	return nil
}

// AddPolicy adds a policy rule to the storage.
func (a *memoryAdapter) AddPolicy(sec string, ptype string, rule []string) error {
	a.policies[ptype] = append(a.policies[ptype], rule)
	return nil
}

// RemovePolicy removes a policy rule from the storage.
func (a *memoryAdapter) RemovePolicy(sec string, ptype string, rule []string) error {
	rules, ok := a.policies[ptype]
	if !ok {
		return nil
	}
	for i, r := range rules {
		if arrayEquals(rule, r) {
			a.policies[ptype] = append(rules[:i], rules[i+1:]...)
			break
		}
	}
	return nil
}

// RemoveFilteredPolicy removes policy rules that match the filter from the storage.
func (a *memoryAdapter) RemoveFilteredPolicy(sec string, ptype string, fieldIndex int, fieldValues ...string) error {
	rules, ok := a.policies[ptype]
	if !ok {
		return nil
	}
	var newRules [][]string
	for _, r := range rules {
		if !arrayEquals(fieldValues, r[fieldIndex:fieldIndex+len(fieldValues)]) {
			newRules = append(newRules, r)
		}
	}
	a.policies[ptype] = newRules
	return nil
}
