/*
 * Copyright (c) 2024 OrigAdmin. All rights reserved.
 */

package jwt

import (
	"testing"
	"time"

	jwtv5 "github.com/golang-jwt/jwt/v5"
)

func TestClaims_Get(t *testing.T) {
	now := time.Now()
	claims := &Claims{
		RegisteredClaims: jwtv5.RegisteredClaims{
			Issuer:    "test-issuer",
			Subject:   "user123",
			Audience:  []string{"test-audience"},
			ExpiresAt: jwtv5.NewNumericDate(now.Add(time.Hour)),
			IssuedAt:  jwtv5.NewNumericDate(now),
			NotBefore: jwtv5.NewNumericDate(now),
			ID:        "token123",
		},
		Roles:       []string{"admin", "user"},
		Permissions: []string{"read", "write"},
		Scopes:      map[string]bool{"read": true, "write": false},
	}

	tests := []struct {
		name     string
		key      string
		want     interface{}
		wantBool bool
	}{
		{"Standard claims - sub", "sub", "user123", true},
		{"Standard claims - iss", "iss", "test-issuer", true},
		{"Standard claims - aud", "aud", []string{"test-audience"}, true},
		{"Standard claims - exp", "exp", now.Add(time.Hour).Unix(), true},
		{"Standard claims - iat", "iat", now.Unix(), true},
		{"Standard claims - nbf", "nbf", now.Unix(), true},
		{"Standard claims - jti", "jti", "token123", true},
		{"Custom claims - roles", "roles", []string{"admin", "user"}, true},
		{"Custom claims - permissions", "permissions", []string{"read", "write"}, true},
		{"Custom claims - scopes", "scopes", map[string]bool{"read": true, "write": false}, true},
		{"Non-existent key", "nonexistent", nil, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := claims.Get(tt.key)
			if ok != tt.wantBool {
				t.Errorf("Claims.Get() ok = %v, want %v", ok, tt.wantBool)
				return
			}
			if ok && !equalValues(got, tt.want) {
				t.Errorf("Claims.Get() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestClaims_GetString(t *testing.T) {
	claims := &Claims{
		RegisteredClaims: jwtv5.RegisteredClaims{
			Issuer:  "test-issuer",
			Subject: "user123",
			ID:      "token123",
		},
	}

	tests := []struct {
		name   string
		key    string
		want   string
		wantOK bool
	}{
		{"Existing string", "sub", "user123", true},
		{"Existing string", "iss", "test-issuer", true},
		{"Existing string", "jti", "token123", true},
		{"Non-string value", "exp", "", false},
		{"Non-existent key", "nonexistent", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := claims.GetString(tt.key)
			if ok != tt.wantOK {
				t.Errorf("Claims.GetString() ok = %v, want %v", ok, tt.wantOK)
				return
			}
			if ok && got != tt.want {
				t.Errorf("Claims.GetString() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestClaims_GetStringSlice(t *testing.T) {
	claims := &Claims{
		Roles:       []string{"admin", "user"},
		Permissions: []string{"read", "write"},
		RegisteredClaims: jwtv5.RegisteredClaims{
			Audience: []string{"aud1", "aud2"},
		},
	}

	tests := []struct {
		name   string
		key    string
		want   []string
		wantOK bool
	}{
		{"Roles", "roles", []string{"admin", "user"}, true},
		{"Permissions", "permissions", []string{"read", "write"}, true},
		{"Audience", "aud", []string{"aud1", "aud2"}, true},
		{"Non-slice value", "sub", nil, false},
		{"Non-existent key", "nonexistent", nil, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := claims.GetStringSlice(tt.key)
			if ok != tt.wantOK {
				t.Errorf("Claims.GetStringSlice() ok = %v, want %v", ok, tt.wantOK)
				return
			}
			if ok && !equalStringSlices(got, tt.want) {
				t.Errorf("Claims.GetStringSlice() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestClaims_UnmarshalValue(t *testing.T) {
	claims := &Claims{
		Roles:       []string{"admin", "user"},
		Permissions: []string{"read", "write"},
		Scopes:      map[string]bool{"read": true, "write": false},
	}

	t.Run("Unmarshal roles", func(t *testing.T) {
		var roles []string
		err := claims.UnmarshalValue("roles", &roles)
		if err != nil {
			t.Errorf("Claims.UnmarshalValue() error = %v", err)
			return
		}
		if !equalStringSlices(roles, []string{"admin", "user"}) {
			t.Errorf("Claims.UnmarshalValue() = %v, want %v", roles, []string{"admin", "user"})
		}
	})

	t.Run("Unmarshal scopes", func(t *testing.T) {
		var scopes map[string]bool
		err := claims.UnmarshalValue("scopes", &scopes)
		if err != nil {
			t.Errorf("Claims.UnmarshalValue() error = %v", err)
			return
		}
		if !equalMaps(scopes, map[string]bool{"read": true, "write": false}) {
			t.Errorf("Claims.UnmarshalValue() = %v, want %v", scopes, map[string]bool{"read": true, "write": false})
		}
	})

	t.Run("Non-existent key", func(t *testing.T) {
		var value string
		err := claims.UnmarshalValue("nonexistent", &value)
		if err == nil {
			t.Error("Claims.UnmarshalValue() expected error for non-existent key")
		}
	})
}

func TestClaims_Export(t *testing.T) {
	now := time.Now()
	claims := &Claims{
		RegisteredClaims: jwtv5.RegisteredClaims{
			Issuer:    "test-issuer",
			Subject:   "user123",
			Audience:  []string{"test-audience"},
			ExpiresAt: jwtv5.NewNumericDate(now.Add(time.Hour)),
			IssuedAt:  jwtv5.NewNumericDate(now),
			NotBefore: jwtv5.NewNumericDate(now),
			ID:        "token123",
		},
		Roles:       []string{"admin", "user"},
		Permissions: []string{"read", "write"},
		Scopes:      map[string]bool{"read": true, "write": false},
	}

	exported := claims.Export()
	if exported == nil {
		t.Error("Claims.Export() returned nil")
		return
	}

	// Check some key fields
	if val, ok := exported["sub"]; !ok || val.GetStringValue() != "user123" {
		t.Errorf("Exported claims missing or incorrect 'sub': %v", val)
	}

	if _, ok := exported["roles"]; !ok {
		t.Error("Exported claims missing 'roles'")
	}
}

// Helper functions for comparison
func equalValues(a, b interface{}) bool {
	switch av := a.(type) {
	case string:
		bv, ok := b.(string)
		return ok && av == bv
	case int64:
		bv, ok := b.(int64)
		return ok && av == bv
	case []string:
		bv, ok := b.([]string)
		return ok && equalStringSlices(av, bv)
	case jwtv5.ClaimStrings:
		// Handle JWT audience which is of type ClaimStrings
		bv, ok := b.([]string)
		if !ok {
			return false
		}
		return equalStringSlices([]string(av), bv)
	case map[string]bool:
		bv, ok := b.(map[string]bool)
		return ok && equalMaps(av, bv)
	default:
		return false
	}
}

func equalStringSlices(a, b []string) bool {
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

func equalMaps(a, b map[string]bool) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if bv, ok := b[k]; !ok || bv != v {
			return false
		}
	}
	return true
}
