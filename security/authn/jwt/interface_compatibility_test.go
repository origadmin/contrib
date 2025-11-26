/*
 * Copyright (c) 2024 OrigAdmin. All rights reserved.
 */

package jwt

import (
	"testing"
	"time"

	jwtv5 "github.com/golang-jwt/jwt/v5"

	"github.com/origadmin/contrib/security"
)

// TestClaimsInterfaceCompatibility tests that JWT Claims implements security.Claims interface
func TestClaimsInterfaceCompatibility(t *testing.T) {
	// This test ensures that *Claims implements security.Claims interface
	var _ security.Claims = (*Claims)(nil)

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

	// Test all interface methods
	t.Run("Get method", func(t *testing.T) {
		// Test standard JWT claims
		if val, ok := claims.Get("sub"); !ok || val != "user123" {
			t.Errorf("Get('sub') = %v, %v; want 'user123', true", val, ok)
		}

		if val, ok := claims.Get("iss"); !ok || val != "test-issuer" {
			t.Errorf("Get('iss') = %v, %v; want 'test-issuer', true", val, ok)
		}

		// Test custom claims
		if val, ok := claims.Get("roles"); !ok {
			t.Errorf("Get('roles') = %v, %v; want non-nil, true", val, ok)
		}
	})

	t.Run("GetString method", func(t *testing.T) {
		if val, ok := claims.GetString("sub"); !ok || val != "user123" {
			t.Errorf("GetString('sub') = %v, %v; want 'user123', true", val, ok)
		}

		if val, ok := claims.GetString("iss"); !ok || val != "test-issuer" {
			t.Errorf("GetString('iss') = %v, %v; want 'test-issuer', true", val, ok)
		}

		// Test non-string value
		if val, ok := claims.GetString("exp"); ok {
			t.Errorf("GetString('exp') should fail for non-string value, got %v", val)
		}
	})

	t.Run("GetInt64 method", func(t *testing.T) {
		if val, ok := claims.GetInt64("exp"); !ok || val != now.Add(time.Hour).Unix() {
			t.Errorf("GetInt64('exp') = %v, %v; want %d, true", val, ok, now.Add(time.Hour).Unix())
		}

		if val, ok := claims.GetInt64("iat"); !ok || val != now.Unix() {
			t.Errorf("GetInt64('iat') = %v, %v; want %d, true", val, ok, now.Unix())
		}

		// Test non-int64 value
		if val, ok := claims.GetInt64("sub"); ok {
			t.Errorf("GetInt64('sub') should fail for non-int64 value, got %v", val)
		}
	})

	t.Run("GetStringSlice method", func(t *testing.T) {
		if val, ok := claims.GetStringSlice("roles"); !ok || len(val) != 2 {
			t.Errorf("GetStringSlice('roles') = %v, %v; want slice with 2 elements, true", val, ok)
		}

		if val, ok := claims.GetStringSlice("aud"); !ok || len(val) != 1 || val[0] != "test-audience" {
			t.Errorf("GetStringSlice('aud') = %v, %v; want ['test-audience'], true", val, ok)
		}

		// Test non-slice value
		if val, ok := claims.GetStringSlice("sub"); ok {
			t.Errorf("GetStringSlice('sub') should fail for non-slice value, got %v", val)
		}
	})

	t.Run("GetMap method", func(t *testing.T) {
		if val, ok := claims.GetMap("scopes"); !ok || len(val) != 2 {
			t.Errorf("GetMap('scopes') = %v, %v; want map with 2 elements, true", val, ok)
		}

		if val, ok := claims.GetMap("scopes"); ok {
			if read, exists := val["read"]; !exists || read != true {
				t.Errorf("GetMap('scopes')['read'] = %v, %v; want true, true", read, exists)
			}
		}

		// Test non-map value
		if val, ok := claims.GetMap("sub"); ok {
			t.Errorf("GetMap('sub') should fail for non-map value, got %v", val)
		}
	})

	t.Run("UnmarshalValue method", func(t *testing.T) {
		// Test unmarshaling roles
		var roles []string
		if err := claims.UnmarshalValue("roles", &roles); err != nil {
			t.Errorf("UnmarshalValue('roles') error = %v", err)
		}
		if len(roles) != 2 {
			t.Errorf("Unmarshaled roles length = %d, want 2", len(roles))
		}

		// Test unmarshaling scopes
		var scopes map[string]bool
		if err := claims.UnmarshalValue("scopes", &scopes); err != nil {
			t.Errorf("UnmarshalValue('scopes') error = %v", err)
		}
		if len(scopes) != 2 {
			t.Errorf("Unmarshaled scopes length = %d, want 2", len(scopes))
		}

		// Test non-existent key
		var dummy string
		if err := claims.UnmarshalValue("nonexistent", &dummy); err == nil {
			t.Error("UnmarshalValue('nonexistent') should return error")
		}
	})

	t.Run("Export method", func(t *testing.T) {
		exported := claims.Export()
		if exported == nil {
			t.Error("Export() returned nil")
		}

		// Check that standard claims are exported
		if _, ok := exported["sub"]; !ok {
			t.Error("Exported claims missing 'sub'")
		}

		if _, ok := exported["iss"]; !ok {
			t.Error("Exported claims missing 'iss'")
		}

		// Check that custom claims are exported
		if _, ok := exported["roles"]; !ok {
			t.Error("Exported claims missing 'roles'")
		}
	})
}

// TestClaimsConversionToSecurityClaims tests conversion between JWT Claims and security.Claims
func TestClaimsConversionToSecurityClaims(t *testing.T) {
	now := time.Now()
	jwtClaims := &Claims{
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

	// Test assignment to security.Claims interface
	var securityClaims security.Claims = jwtClaims

	// Test that we can use all security.Claims methods
	t.Run("Interface assignment and usage", func(t *testing.T) {
		// Test Get method
		if val, ok := securityClaims.Get("sub"); !ok || val != "user123" {
			t.Errorf("securityClaims.Get('sub') = %v, %v; want 'user123', true", val, ok)
		}

		// Test GetString method
		if val, ok := securityClaims.GetString("sub"); !ok || val != "user123" {
			t.Errorf("securityClaims.GetString('sub') = %v, %v; want 'user123', true", val, ok)
		}

		// Test GetInt64 method
		if val, ok := securityClaims.GetInt64("exp"); !ok || val != now.Add(time.Hour).Unix() {
			t.Errorf("securityClaims.GetInt64('exp') = %v, %v; want %d, true", val, ok, now.Add(time.Hour).Unix())
		}

		// Test GetStringSlice method
		if val, ok := securityClaims.GetStringSlice("roles"); !ok || len(val) != 2 {
			t.Errorf("securityClaims.GetStringSlice('roles') = %v, %v; want slice with 2 elements, true", val, ok)
		}

		// Test GetMap method
		if val, ok := securityClaims.GetMap("scopes"); !ok || len(val) != 2 {
			t.Errorf("securityClaims.GetMap('scopes') = %v, %v; want map with 2 elements, true", val, ok)
		}

		// Test UnmarshalValue method
		var roles []string
		if err := securityClaims.UnmarshalValue("roles", &roles); err != nil {
			t.Errorf("securityClaims.UnmarshalValue('roles') error = %v", err)
		}

		// Test Export method
		exported := securityClaims.Export()
		if exported == nil {
			t.Error("securityClaims.Export() returned nil")
		}
	})
}
