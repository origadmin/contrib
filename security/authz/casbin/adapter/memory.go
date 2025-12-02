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

// NewWithPolicies creates a new in-memory adapter with pre-defined policies.
func NewWithPolicies(policies map[string][][]string) *Adapter {
	return &Adapter{
		policies: policies,
	}
}

// NewMemory creates a new in-memory adapter.
func NewMemory() *Adapter {
	return &Adapter{
		policies: make(map[string][][]string),
	}
}

// LoadPolicy loads all policy rules from the storage.
func (a *Adapter) LoadPolicy(m model.Model) error {
	for ptype, rules := range a.policies {
		for _, rule := range rules {
			line := ptype + ", " + strings.Join(rule, ", ")
			if err := persist.LoadPolicyLine(line, m); err != nil {
				return err
			}
		}
	}
	return nil
}

// SavePolicy saves all policy rules to the storage.
func (a *Adapter) SavePolicy(m model.Model) error {
	a.policies = make(map[string][][]string)
	a.savePoliciesFromSection("p", m)
	a.savePoliciesFromSection("g", m)
	return nil
}

// savePoliciesFromSection saves policies for a given section (e.g., "p" or "g").
func (a *Adapter) savePoliciesFromSection(sec string, m model.Model) {
	if astMap, ok := m[sec]; ok {
		for ptype, ast := range astMap {
			if _, exists := a.policies[ptype]; !exists {
				a.policies[ptype] = make([][]string, 0, len(ast.Policy))
			}
			a.policies[ptype] = append(a.policies[ptype], ast.Policy...)
		}
	}
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

// arrayEquals checks if two string slices are equal.
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
