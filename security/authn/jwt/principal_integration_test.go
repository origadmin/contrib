/*
 * Copyright (c) 2024 OrigAdmin. All rights reserved.
 */

package jwt

import (
	"testing"
	"time"

	jwtv5 "github.com/golang-jwt/jwt/v5"

	"github.com/origadmin/contrib/security"
	"github.com/origadmin/contrib/security/principal"
)

// TestPrincipalWithJWTClaims tests that Principal can work seamlessly with JWT Claims
func TestPrincipalWithJWTClaims(t *testing.T) {
	// Create JWT Claims
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

	// Create Principal with JWT Claims
	princ := principal.New(
		"user123",
		[]string{"admin", "user"},
		[]string{"read", "write"},
		map[string]bool{"read": true, "write": false},
		jwtClaims,
	)

	// Test Principal methods
	t.Run("Principal basic methods", func(t *testing.T) {
		if princ.GetID() != "user123" {
			t.Errorf("GetID() = %v; want 'user123'", princ.GetID())
		}

		roles := princ.GetRoles()
		if len(roles) != 2 || roles[0] != "admin" || roles[1] != "user" {
			t.Errorf("GetRoles() = %v; want [admin, user]", roles)
		}

		permissions := princ.GetPermissions()
		if len(permissions) != 2 || permissions[0] != "read" || permissions[1] != "write" {
			t.Errorf("GetPermissions() = %v; want [read, write]", permissions)
		}

		scopes := princ.GetScopes()
		if !scopes["read"] || scopes["write"] {
			t.Errorf("GetScopes() = %v; want {read: true, write: false}", scopes)
		}
	})

	// Test that Principal's Claims is the JWT Claims
	t.Run("Principal claims integration", func(t *testing.T) {
		claims := princ.GetClaims()
		if claims == nil {
			t.Fatal("GetClaims() returned nil")
		}

		// Test standard JWT claims through Principal
		if val, ok := claims.Get("sub"); !ok || val != "user123" {
			t.Errorf("claims.Get('sub') = %v, %v; want 'user123', true", val, ok)
		}

		if val, ok := claims.Get("iss"); !ok || val != "test-issuer" {
			t.Errorf("claims.Get('iss') = %v, %v; want 'test-issuer', true", val, ok)
		}

		// Test custom claims through Principal
		if val, ok := claims.Get("roles"); !ok {
			t.Errorf("claims.Get('roles') = %v, %v; want non-nil, true", val, ok)
		}

		if val, ok := claims.Get("permissions"); !ok {
			t.Errorf("claims.Get('permissions') = %v, %v; want non-nil, true", val, ok)
		}

		if val, ok := claims.Get("scopes"); !ok {
			t.Errorf("claims.Get('scopes') = %v, %v; want non-nil, true", val, ok)
		}
	})

	// Test interface compatibility - Principal's Claims should implement security.Claims
	t.Run("Interface compatibility", func(t *testing.T) {
		var _ security.Claims = princ.GetClaims()

		claims := princ.GetClaims()

		// Test all security.Claims methods
		if str, ok := claims.GetString("sub"); !ok || str != "user123" {
			t.Errorf("GetString('sub') = %v, %v; want 'user123', true", str, ok)
		}

		if str, ok := claims.GetString("iss"); !ok || str != "test-issuer" {
			t.Errorf("GetString('iss') = %v, %v; want 'test-issuer', true", str, ok)
		}

		if roles, ok := claims.GetStringSlice("roles"); !ok || len(roles) != 2 {
			t.Errorf("GetStringSlice('roles') = %v, %v; want [admin, user], true", roles, ok)
		}

		if permissions, ok := claims.GetStringSlice("permissions"); !ok || len(permissions) != 2 {
			t.Errorf("GetStringSlice('permissions') = %v, %v; want [read, write], true", permissions, ok)
		}

		if scopes, ok := claims.GetMap("scopes"); !ok {
			t.Errorf("GetMap('scopes') = %v, %v; want map, true", scopes, ok)
		}
	})
}

// TestPrincipalExportWithJWTClaims tests that Principal export works with JWT Claims
func TestPrincipalExportWithJWTClaims(t *testing.T) {
	// Create JWT Claims
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

	// Create Principal with JWT Claims
	princ := principal.New(
		"user123",
		[]string{"admin", "user"},
		[]string{"read", "write"},
		map[string]bool{"read": true, "write": false},
		jwtClaims,
	)

	// Export Principal
	protoPrincipal := princ.Export()

	if protoPrincipal == nil {
		t.Fatal("Export() returned nil")
	}

	// Verify exported data
	if protoPrincipal.Id != "user123" {
		t.Errorf("Exported Id = %v; want 'user123'", protoPrincipal.Id)
	}

	if len(protoPrincipal.Roles) != 2 || protoPrincipal.Roles[0] != "admin" || protoPrincipal.Roles[1] != "user" {
		t.Errorf("Exported Roles = %v; want [admin, user]", protoPrincipal.Roles)
	}

	if len(protoPrincipal.Permissions) != 2 || protoPrincipal.Permissions[0] != "read" || protoPrincipal.Permissions[1] != "write" {
		t.Errorf("Exported Permissions = %v; want [read, write]", protoPrincipal.Permissions)
	}

	if !protoPrincipal.Scopes["read"] || protoPrincipal.Scopes["write"] {
		t.Errorf("Exported Scopes = %v; want {read: true, write: false}", protoPrincipal.Scopes)
	}

	// Verify exported claims
	exportedClaims := protoPrincipal.Claims
	if exportedClaims == nil {
		t.Fatal("Exported Claims is nil")
	}

	// Check that JWT claims were properly exported
	if val, ok := exportedClaims["sub"]; !ok || val.AsInterface() != "user123" {
		t.Errorf("Exported claims['sub'] = %v, %v; want 'user123', true", val, ok)
	}

	if val, ok := exportedClaims["iss"]; !ok || val.AsInterface() != "test-issuer" {
		t.Errorf("Exported claims['iss'] = %v, %v; want 'test-issuer', true", val, ok)
	}
}

// TestPrincipalFromProtoWithJWTClaims tests round-trip conversion with JWT Claims
func TestPrincipalFromProtoWithJWTClaims(t *testing.T) {
	// Create JWT Claims
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

	// Create Principal with JWT Claims
	originalPrinc := principal.New(
		"user123",
		[]string{"admin", "user"},
		[]string{"read", "write"},
		map[string]bool{"read": true, "write": false},
		jwtClaims,
	)

	// Export to proto
	protoPrincipal := originalPrinc.Export()

	// Import from proto
	importedPrinc, err := principal.FromProto(protoPrincipal)
	if err != nil {
		t.Fatalf("FromProto() error = %v", err)
	}

	if importedPrinc == nil {
		t.Fatal("FromProto() returned nil")
	}

	// Verify round-trip data integrity
	if importedPrinc.GetID() != originalPrinc.GetID() {
		t.Errorf("Round-trip ID = %v; want %v", importedPrinc.GetID(), originalPrinc.GetID())
	}

	originalRoles := originalPrinc.GetRoles()
	importedRoles := importedPrinc.GetRoles()
	if len(importedRoles) != len(originalRoles) {
		t.Errorf("Round-trip Roles length = %v; want %v", len(importedRoles), len(originalRoles))
	}

	originalPermissions := originalPrinc.GetPermissions()
	importedPermissions := importedPrinc.GetPermissions()
	if len(importedPermissions) != len(originalPermissions) {
		t.Errorf("Round-trip Permissions length = %v; want %v", len(importedPermissions), len(originalPermissions))
	}

	// Verify claims round-trip
	originalClaims := originalPrinc.GetClaims()
	importedClaims := importedPrinc.GetClaims()

	if originalSub, ok := originalClaims.Get("sub"); ok {
		if importedSub, ok := importedClaims.Get("sub"); !ok || importedSub != originalSub {
			t.Errorf("Round-trip claims['sub'] = %v; want %v", importedSub, originalSub)
		}
	}
}

// TestPrincipalWithNilJWTClaims tests Principal behavior with nil JWT Claims
func TestPrincipalWithNilJWTClaims(t *testing.T) {
	// Create Principal with nil Claims
	princ := principal.New(
		"user456",
		[]string{"user"},
		[]string{"read"},
		map[string]bool{"read": true},
		nil,
	)

	// Should still work and provide default claims
	claims := princ.GetClaims()
	if claims == nil {
		t.Fatal("GetClaims() returned nil even when input was nil")
	}

	// Default claims should be empty but functional
	if val, ok := claims.Get("nonexistent"); ok {
		t.Errorf("Default claims Get('nonexistent') = %v, %v; want nil, false", val, ok)
	}
}

// TestPrincipalClaimsTypeAssertion tests type assertion for JWT Claims
func TestPrincipalClaimsTypeAssertion(t *testing.T) {
	// Create JWT Claims
	jwtClaims := &Claims{
		Roles:       []string{"admin"},
		Permissions: []string{"write"},
		Scopes:      map[string]bool{"admin": true},
	}

	// Create Principal with JWT Claims
	princ := principal.New(
		"admin",
		[]string{"admin"},
		[]string{"write"},
		map[string]bool{"admin": true},
		jwtClaims,
	)

	// Test type assertion back to *Claims
	claims := princ.GetClaims()
	if jwtClaims, ok := claims.(*Claims); ok {
		// Now we can access JWT-specific methods
		if len(jwtClaims.Roles) != 1 || jwtClaims.Roles[0] != "admin" {
			t.Errorf("Type-asserted JWT Claims Roles = %v; want [admin]", jwtClaims.Roles)
		}
	} else {
		t.Error("Could not type assert Principal's Claims back to *Claims")
	}
}