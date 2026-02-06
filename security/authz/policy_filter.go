package authz

import (
	authzv1 "github.com/origadmin/contrib/api/gen/go/security/authz/v1"
)

// PolicyFilter is used for querying policies with optional filtering conditions.
// Nil fields act as wildcards (match any value).
// Non-nil fields (including empty strings) are used as exact match filters.
type PolicyFilter struct {
	Type      *string
	Subject   *string
	Actions   []string
	Resources []string
	Effect    *string
	Domain    *string
	Disabled  *bool
}

// PolicyFilterOption is a function that modifies a PolicyFilter.
type PolicyFilterOption func(*PolicyFilter)

// WithFilterType sets the type filter.
func WithFilterType(t string) PolicyFilterOption {
	return func(f *PolicyFilter) {
		f.Type = &t
	}
}

// WithFilterSubject sets the subject filter.
func WithFilterSubject(subject string) PolicyFilterOption {
	return func(f *PolicyFilter) {
		f.Subject = &subject
	}
}

// WithFilterActions sets the actions filter.
func WithFilterActions(actions ...string) PolicyFilterOption {
	return func(f *PolicyFilter) {
		f.Actions = actions
	}
}

// WithFilterResources sets the resources filter.
func WithFilterResources(resources ...string) PolicyFilterOption {
	return func(f *PolicyFilter) {
		f.Resources = resources
	}
}

// WithFilterEffect sets the effect filter.
func WithFilterEffect(effect string) PolicyFilterOption {
	return func(f *PolicyFilter) {
		f.Effect = &effect
	}
}

// WithFilterDomain sets the domain filter.
func WithFilterDomain(domain string) PolicyFilterOption {
	return func(f *PolicyFilter) {
		f.Domain = &domain
	}
}

// WithFilterDisabled sets the disabled filter.
func WithFilterDisabled(disabled bool) PolicyFilterOption {
	return func(f *PolicyFilter) {
		f.Disabled = &disabled
	}
}

// BuildPolicyFilter constructs a PolicyFilter from a base PolicySpec and options.
// The PolicySpec provides base values, and options can override or add to them.
// Only non-zero/non-nil values from PolicySpec are copied to the filter.
func BuildPolicyFilter(base *authzv1.PolicySpec, opts ...PolicyFilterOption) *PolicyFilter {
	filter := &PolicyFilter{}

	if base != nil {
		// Copy non-zero values from PolicySpec to filter
		if base.Type != "" {
			filter.Type = &base.Type
		}
		if base.Subject != "" {
			filter.Subject = &base.Subject
		}
		if len(base.Actions) > 0 {
			filter.Actions = base.Actions
		}
		if len(base.Resources) > 0 {
			filter.Resources = base.Resources
		}
		if base.Effect != nil {
			filter.Effect = base.Effect
		}
		if base.Domain != nil {
			filter.Domain = base.Domain
		}
		if base.Disabled != nil {
			filter.Disabled = base.Disabled
		}
	}

	// Apply options (they can override values from PolicySpec)
	for _, opt := range opts {
		opt(filter)
	}

	return filter
}
