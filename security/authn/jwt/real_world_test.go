/*
 * Copyright (c) 2024 OrigAdmin. All rights reserved.
 */

package jwt

import (
	"context"
	"testing"
	"time"

	jwtv5 "github.com/golang-jwt/jwt/v5"

	securityv1 "github.com/origadmin/contrib/api/gen/go/security/v1"
	"github.com/origadmin/contrib/security"
	"github.com/origadmin/contrib/security/principal"
)

// TestRealWorldUsage demonstrates real-world usage of JWT Claims with security.Claims interface
func TestRealWorldUsage(t *testing.T) {
	// Simulate a real JWT token with custom claims
	now := time.Now()
	jwtClaims := &Claims{
		RegisteredClaims: jwtv5.RegisteredClaims{
			Issuer:    "myapp",
			Subject:   "user123",
			Audience:  []string{"myapp-api"},
			ExpiresAt: jwtv5.NewNumericDate(now.Add(2 * time.Hour)),
			IssuedAt:  jwtv5.NewNumericDate(now),
			NotBefore: jwtv5.NewNumericDate(now),
			ID:        "token-abc123",
		},
		Roles:       []string{"user", "admin"},
		Permissions: []string{"read:users", "write:posts"},
		Scopes:      map[string]bool{"read": true, "write": true, "delete": false},
	}

	// Create a Principal using the JWT Claims
	princ := principal.New(
		jwtClaims.Subject,
		jwtClaims.Roles,
		jwtClaims.Permissions,
		jwtClaims.Scopes,
		jwtClaims, // Pass JWT Claims as security.Claims
	)

	// Test that we can access claims through the Principal
	t.Run("Principal with JWT Claims", func(t *testing.T) {
		claims := princ.GetClaims()
		if claims == nil {
			t.Fatal("Principal claims is nil")
		}

		// Access standard JWT claims through security.Claims interface
		if userID, ok := claims.GetString("sub"); !ok || userID != "user123" {
			t.Errorf("Expected user ID 'user123', got '%s'", userID)
		}

		if issuer, ok := claims.GetString("iss"); !ok || issuer != "myapp" {
			t.Errorf("Expected issuer 'myapp', got '%s'", issuer)
		}

		// Access custom claims through security.Claims interface
		if roles, ok := claims.GetStringSlice("roles"); !ok || len(roles) != 2 {
			t.Errorf("Expected 2 roles, got %d", len(roles))
		}

		if scopes, ok := claims.GetMap("scopes"); !ok || len(scopes) != 3 {
			t.Errorf("Expected 3 scopes, got %d", len(scopes))
		}
	})

	// Test type assertion back to JWT Claims
	t.Run("Type assertion back to JWT Claims", func(t *testing.T) {
		claims := princ.GetClaims()

		// Type assertion to get back the original JWT Claims
		if jwtClaims, ok := claims.(*Claims); ok {
			// Now we can access JWT-specific fields
			if jwtClaims.Subject != "user123" {
				t.Errorf("Expected subject 'user123', got '%s'", jwtClaims.Subject)
			}

			if len(jwtClaims.Audience) != 1 || jwtClaims.Audience[0] != "myapp-api" {
				t.Errorf("Expected audience ['myapp-api'], got %v", jwtClaims.Audience)
			}
		} else {
			t.Error("Failed to type assert claims back to *Claims")
		}
	})

	// Test passing JWT Claims to functions expecting security.Claims
	t.Run("Function expecting security.Claims", func(t *testing.T) {
		// A function that works with any security.Claims implementation
		checkUserPermissions := func(claims security.Claims) bool {
			// Check if user has admin role
			roles, ok := claims.GetStringSlice("roles")
			if !ok {
				return false
			}

			for _, role := range roles {
				if role == "admin" {
					return true
				}
			}
			return false
		}

		// Pass our JWT Claims to the function
		isAdmin := checkUserPermissions(jwtClaims)
		if !isAdmin {
			t.Error("Expected user to have admin role")
		}
	})

	// Test serialization/deserialization through Export
	t.Run("Export and reconstruct", func(t *testing.T) {
		claims := princ.GetClaims()
		exported := claims.Export()

		if exported == nil {
			t.Fatal("Export returned nil")
		}

		// Verify exported data contains all expected fields
		expectedFields := []string{"sub", "iss", "aud", "exp", "iat", "nbf", "jti", "roles", "permissions", "scopes"}
		for _, field := range expectedFields {
			if _, exists := exported[field]; !exists {
				t.Errorf("Exported claims missing field: %s", field)
			}
		}
	})
}

// TestClaimsInMiddlewareContext simulates how JWT Claims would be used in middleware
func TestClaimsInMiddlewareContext(t *testing.T) {
	// Simulate middleware that extracts and validates JWT
	processRequest := func(ctx context.Context, claims security.Claims) error {
		// Check if token is expired
		if exp, ok := claims.GetInt64("exp"); ok {
			if time.Now().Unix() > exp {
				return securityv1.ErrorTokenExpired("token has expired")
			}
		}

		// Check required scopes
		if scopes, ok := claims.GetMap("scopes"); ok {
			if read, exists := scopes["read"]; !exists || !read.(bool) {
				return securityv1.ErrorPermissionDenied("read scope required")
			}
		}

		// Add claims to context for downstream handlers
		ctx = context.WithValue(ctx, "claims", claims)
		return nil
	}

	// Create JWT Claims
	now := time.Now()
	jwtClaims := &Claims{
		RegisteredClaims: jwtv5.RegisteredClaims{
			Subject:   "user123",
			ExpiresAt: jwtv5.NewNumericDate(now.Add(time.Hour)),
			IssuedAt:  jwtv5.NewNumericDate(now),
		},
		Scopes: map[string]bool{"read": true, "write": false},
	}

	// Test the middleware function
	t.Run("Middleware processing", func(t *testing.T) {
		err := processRequest(context.Background(), jwtClaims)
		if err != nil {
			t.Errorf("Middleware processing failed: %v", err)
		}
	})

	// Test with expired token
	t.Run("Expired token", func(t *testing.T) {
		expiredClaims := &Claims{
			RegisteredClaims: jwtv5.RegisteredClaims{
				Subject:   "user123",
				ExpiresAt: jwtv5.NewNumericDate(now.Add(-time.Hour)), // Expired
				IssuedAt:  jwtv5.NewNumericDate(now.Add(-2 * time.Hour)),
			},
			Scopes: map[string]bool{"read": true},
		}

		err := processRequest(context.Background(), expiredClaims)
		if err == nil {
			t.Error("Expected error for expired token")
		}
	})
}
