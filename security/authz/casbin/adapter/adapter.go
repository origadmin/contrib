/*
 * Copyright (c) 2024 OrigAdmin. All rights reserved.
 */

// Package adapter is the memory adapter for Casbin.
package adapter

import (
	"strings"

	"github.com/casbin/casbin/v2/model"
	"github.com/casbin/casbin/v2/persist"
)

// Adapter is an in-memory adapter for Casbin.
// It's useful for testing or for scenarios where policies are not persisted.
type Adapter struct {
	policies map[string][][]string
}

// NewMemory creates a new in-memory adapter.
func NewMemory() persist.Adapter {
	return &Adapter{
		policies: make(map[string][][]string),
	}
}

// LoadPolicy loads all policy rules from the storage.
func (a *Adapter) LoadPolicy(m model.Model) error {
	for ptype, rules := range a.policies {
		for _, rule := range rules {
			line := ptype + ", " + strings.Join(rule, ", ")
			err := persist.LoadPolicyLine(line, m)
			if err != nil {
				return err
			}
		}
	}
	return nil
}

// SavePolicy saves all policy rules to the storage.
func (a *Adapter) SavePolicy(m model.Model) error {
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
func (a *Adapter) AddPolicy(sec string, ptype string, rule []string) error {
	a.policies[ptype] = append(a.policies[ptype], rule)
	return nil
}

// RemovePolicy removes a policy rule from the storage.
func (a *Adapter) RemovePolicy(sec string, ptype string, rule []string) error {
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
func (a *Adapter) RemoveFilteredPolicy(sec string, ptype string, fieldIndex int, fieldValues ...string) error {
	rules, ok := a.policies[ptype]
	if !ok {
		return nil
	}
	var newRules [][]string
	for _, r := range rules {
		if fieldIndex > len(r) || fieldIndex+len(fieldValues) > len(r) {
			newRules = append(newRules, r)
			continue
		}
		if arrayEquals(fieldValues, r[fieldIndex:fieldIndex+len(fieldValues)]) {
			continue
		}
		newRules = append(newRules, r)
	}
	a.policies[ptype] = newRules
	return nil
}

func arrayEquals(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i, v := range a {
		if v != b[i] {
			return false
		}
	}
	return true
}
