// Package jwt implements the functions, types, and interfaces for the module.
package jwt

import (
	"encoding/json"
	"fmt"

	jwtv5 "github.com/golang-jwt/jwt/v5"
	"google.golang.org/protobuf/types/known/structpb"
)

// Claims represents the JWT claims, including standard claims and custom ones.
type Claims struct {
	jwtv5.RegisteredClaims
	Roles       []string        `json:"roles,omitempty"`
	Permissions []string        `json:"permissions,omitempty"`
	Scopes      map[string]bool `json:"scopes,omitempty"`
}

func (c *Claims) UnmarshalValue(key string, target any) error {
	val, ok := c.Get(key)
	if !ok {
		return fmt.Errorf("key '%s' not found in claims", key)
	}

	// Use JSON marshaling for type conversion
	data, err := json.Marshal(val)
	if err != nil {
		return fmt.Errorf("failed to marshal value for key '%s': %w", key, err)
	}

	return json.Unmarshal(data, target)
}

func (c *Claims) Get(key string) (interface{}, bool) {
	// Check custom fields first
	switch key {
	case "roles":
		return c.Roles, true
	case "permissions":
		return c.Permissions, true
	case "scopes":
		return c.Scopes, true
	}

	// Check standard JWT claims
	switch key {
	case "sub":
		if c.Subject != "" {
			return c.Subject, true
		}
	case "iss":
		if c.Issuer != "" {
			return c.Issuer, true
		}
	case "aud":
		if len(c.Audience) > 0 {
			return c.Audience, true
		}
	case "exp":
		if c.ExpiresAt != nil {
			return c.ExpiresAt.Unix(), true
		}
	case "iat":
		if c.IssuedAt != nil {
			return c.IssuedAt.Unix(), true
		}
	case "nbf":
		if c.NotBefore != nil {
			return c.NotBefore.Unix(), true
		}
	case "jti":
		if c.ID != "" {
			return c.ID, true
		}
	}

	return nil, false
}

func (c *Claims) GetString(key string) (string, bool) {
	if val, ok := c.Get(key); ok {
		if str, ok := val.(string); ok {
			return str, true
		}
	}
	return "", false
}

func (c *Claims) GetInt64(key string) (int64, bool) {
	if val, ok := c.Get(key); ok {
		if i, ok := val.(int64); ok {
			return i, true
		}
	}
	return 0, false
}

func (c *Claims) GetFloat64(key string) (float64, bool) {
	if val, ok := c.Get(key); ok {
		if f, ok := val.(float64); ok {
			return f, true
		}
	}
	return 0, false
}

func (c *Claims) GetBool(key string) (bool, bool) {
	if val, ok := c.Get(key); ok {
		if b, ok := val.(bool); ok {
			return b, true
		}
	}
	return false, false
}

func (c *Claims) GetStringSlice(key string) ([]string, bool) {
	val, ok := c.Get(key)
	if !ok {
		return nil, false
	}

	switch v := val.(type) {
	case []string:
		return v, true
	case jwtv5.ClaimStrings:
		// Handle JWT audience which is of type ClaimStrings
		return []string(v), true
	case []interface{}:
		result := make([]string, len(v))
		for i, item := range v {
			if str, ok := item.(string); ok {
				result[i] = str
			} else {
				return nil, false
			}
		}
		return result, true

	default:
		return nil, false
	}
}

func (c *Claims) GetMap(key string) (map[string]any, bool) {
	val, ok := c.Get(key)
	if !ok {
		return nil, false
	}

	switch v := val.(type) {
	case map[string]any:
		return v, true
	case map[string]bool:
		// Handle map[string]bool (like scopes)
		result := make(map[string]any)
		for k, val := range v {
			result[k] = val
		}
		return result, true
	case map[interface{}]interface{}:
		result := make(map[string]any)
		for k, val := range v {
			if strKey, ok := k.(string); ok {
				result[strKey] = val
			} else {
				return nil, false
			}
		}
		return result, true
	default:
		return nil, false
	}
}

func (c *Claims) Export() map[string]*structpb.Value {
	data, err := json.Marshal(c)
	if err != nil {
		return nil
	}
	var m map[string]interface{}
	if err := json.Unmarshal(data, &m); err != nil {
		return nil
	}
	st, err := structpb.NewStruct(m)
	if err != nil {
		return nil
	}
	return st.GetFields()
}
