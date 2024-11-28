/*
 * Copyright (c) 2024 OrigAdmin. All rights reserved.
 */

// Package jwt provides functions for generating and validating JWT tokens.
package jwt

import (
	"context"
	"fmt"
	"testing"

	"github.com/origadmin/toolkits/security"
	"github.com/stretchr/testify/assert"
)

func TestAuth(t *testing.T) {
	//cache := memory.NewCache(memory.Config{CleanupInterval: time.Second})
	//c:=security.WithCache(cache)
	store := security.NewTokenStorage()
	ctx := context.Background()

	jwtAuth := security.NewSecurity(NewTokenSerializer(), security.WithStorage(store))

	userID := "test"
	token, err := jwtAuth.GenerateToken(ctx, userID)
	assert.Nil(t, err)
	assert.NotNil(t, token)
	t.Log("token: ", token.AccessToken)
	resultID, err := jwtAuth.ParseSubject(ctx, token.AccessToken)
	assert.Nil(t, err)
	fmt.Println("error", err)
	fmt.Println("result_id:", resultID)
	fmt.Println("user_id: ", userID)
	assert.Equal(t, userID, resultID)
	err = jwtAuth.ValidateAccess(ctx, token.AccessToken)
	assert.Nil(t, err)
	err = jwtAuth.DestroyToken(ctx, token.AccessToken)
	assert.Nil(t, err)
	err = jwtAuth.ValidateAccess(ctx, token.AccessToken)
	assert.NotNil(t, err)
	//time.Sleep(time.Second)
	t.Log("token: ", token.AccessToken)
	resultID, err = jwtAuth.ParseSubject(ctx, token.AccessToken)
	assert.NotNil(t, err)
	assert.EqualError(t, err, ErrInvalidToken.Error())
	assert.Empty(t, resultID)

	err = jwtAuth.Release(ctx)
	assert.Nil(t, err)
}
