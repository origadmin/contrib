/*
 * Copyright (c) 2024 OrigAdmin. All rights reserved.
 */

package jwt

import (
	"testing"
	"time"

	jwtv5 "github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestClaims(t *testing.T) {
	now := time.Now()
	claims := &Claims{
		RegisteredClaims: jwtv5.RegisteredClaims{
			Issuer:    "test-issuer",
			Subject:   "user123",
			Audience:  jwtv5.ClaimStrings{"test-audience"},
			ExpiresAt: jwtv5.NewNumericDate(now.Add(time.Hour)),
			IssuedAt:  jwtv5.NewNumericDate(now),
			NotBefore: jwtv5.NewNumericDate(now),
			ID:        "token123",
		},
		Roles:       []string{"admin", "user"},
		Permissions: []string{"read", "write"},
		Scopes:      map[string]bool{"read": true, "write": false},
	}

	t.Run("Get", func(t *testing.T) {
		// Standard claims
		val, ok := claims.Get("sub")
		assert.True(t, ok)
		assert.Equal(t, "user123", val)

		exp, ok := claims.Get("exp")
		assert.True(t, ok)
		assert.Equal(t, now.Add(time.Hour).Unix(), exp)

		// Custom claims
		roles, ok := claims.Get("roles")
		assert.True(t, ok)
		assert.Equal(t, []string{"admin", "user"}, roles)

		// Non-existent key
		_, ok = claims.Get("nonexistent")
		assert.False(t, ok)
	})

	t.Run("GetString", func(t *testing.T) {
		sub, ok := claims.GetString("sub")
		assert.True(t, ok)
		assert.Equal(t, "user123", sub)

		_, ok = claims.GetString("exp") // Not a string
		assert.False(t, ok)
	})

	t.Run("GetStringSlice", func(t *testing.T) {
		roles, ok := claims.GetStringSlice("roles")
		assert.True(t, ok)
		assert.Equal(t, []string{"admin", "user"}, roles)

		aud, ok := claims.GetStringSlice("aud")
		assert.True(t, ok)
		assert.Equal(t, []string{"test-audience"}, aud)

		_, ok = claims.GetStringSlice("sub") // Not a slice
		assert.False(t, ok)
	})

	t.Run("GetInt64", func(t *testing.T) {
		exp, ok := claims.GetInt64("exp")
		assert.True(t, ok)
		assert.Equal(t, now.Add(time.Hour).Unix(), exp)

		_, ok = claims.GetInt64("sub") // Not an int64
		assert.False(t, ok)
	})

	t.Run("GetMap", func(t *testing.T) {
		scopes, ok := claims.GetMap("scopes")
		assert.True(t, ok)
		assert.Equal(t, map[string]interface{}{"read": true, "write": false}, scopes)

		_, ok = claims.GetMap("sub") // Not a map
		assert.False(t, ok)
	})

	t.Run("UnmarshalValue", func(t *testing.T) {
		var roles []string
		err := claims.UnmarshalValue("roles", &roles)
		require.NoError(t, err)
		assert.Equal(t, []string{"admin", "user"}, roles)

		var scopes map[string]bool
		err = claims.UnmarshalValue("scopes", &scopes)
		require.NoError(t, err)
		assert.Equal(t, map[string]bool{"read": true, "write": false}, scopes)

		var dummy string
		err = claims.UnmarshalValue("nonexistent", &dummy)
		assert.Error(t, err)
	})

	t.Run("Export", func(t *testing.T) {
		exported := claims.Export()
		require.NotNil(t, exported)

		// Check standard claims
		sub, ok := exported["sub"]
		require.True(t, ok)
		assert.Equal(t, "user123", sub.GetStringValue())

		// Check custom claims
		rolesVal, ok := exported["roles"]
		require.True(t, ok)
		roleList := rolesVal.GetListValue()
		require.NotNil(t, roleList)
		assert.Len(t, roleList.Values, 2)
		assert.Equal(t, "admin", roleList.Values[0].GetStringValue())
		assert.Equal(t, "user", roleList.Values[1].GetStringValue())

		// Check map claims
		scopesVal, ok := exported["scopes"]
		require.True(t, ok)
		scopeMap := scopesVal.GetStructValue()
		require.NotNil(t, scopeMap)
		assert.True(t, scopeMap.Fields["read"].GetBoolValue())
		assert.False(t, scopeMap.Fields["write"].GetBoolValue())
	})
}
