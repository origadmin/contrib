/*
 * Copyright (c) 2024 OrigAdmin. All rights reserved.
 */

// Package jwt provides functions for generating and validating JWT tokens.
package jwt

import (
	"time"

	"github.com/goexts/generic/settings"
	"github.com/golang-jwt/jwt/v5"
	"github.com/origadmin/toolkits/errors"
	"github.com/origadmin/toolkits/idgen"
	"github.com/origadmin/toolkits/security"
)

const ErrInvalidToken = errors.String("invalid token")

const (
	defaultDomain    = "localhost"
	defaultExpired   = 7200
	defaultTokenType = "Bearer"
	defaultKey       = "CG24SDVP8OHPK395GB5G"
)

type Claims security.Claims

func (c *Claims) GetExpirationTime() (*jwt.NumericDate, error) {
	return jwt.NewNumericDate(time.Unix(c.ExpiresAt, 0)), nil
}
func (c *Claims) GetIssuedAt() (*jwt.NumericDate, error) {
	return jwt.NewNumericDate(time.Unix(c.IssuedAt, 0)), nil
}
func (c *Claims) GetNotBefore() (*jwt.NumericDate, error) {
	return jwt.NewNumericDate(time.Unix(c.NotBefore, 0)), nil
}
func (c *Claims) GetIssuer() (string, error) {
	return c.Issuer, nil
}
func (c *Claims) GetSubject() (string, error) {
	return c.Subject, nil
}
func (c *Claims) GetAudience() (jwt.ClaimStrings, error) {
	return c.Audience, nil
}

type SerializeSetting = func(*Serialize)

type Serialize struct {
	Parser    *jwt.Parser
	Domain    string
	TokenType string
	Expired   time.Duration
	Method    jwt.SigningMethod
	Key       []byte
	OldKey    []byte
	KeyFns    []func(*jwt.Token) (any, error)
}

var (
	defaultMethod = jwt.SigningMethodHS512
)

func (s Serialize) Generate(subject string, expires ...time.Duration) security.Token {
	now := time.Now()
	expired := s.Expired
	if len(expires) > 0 {
		expired = expires[0]
	}
	expiresAt := now.Add(expired * time.Second)
	token := security.Token{
		AccessToken:  "",
		TokenType:    s.TokenType,
		RefreshToken: "",
		Expiry:       expiresAt,
		ExpiresIn:    int64(expired),
		Claims: &security.Claims{
			ID:        idgen.GenID(),
			Subject:   subject,
			Issuer:    s.Domain,
			IssuedAt:  now.Unix(),
			ExpiresAt: expiresAt.Unix(),
			NotBefore: now.Unix(),
		},
	}
	jwtToken := jwt.NewWithClaims(s.Method, (*Claims)(token.Claims))
	if tokenStr, err := jwtToken.SignedString(s.Key); err == nil {
		token.AccessToken = tokenStr
	}
	return token
}

func (s Serialize) Parse(tokenStr string) (security.Token, error) {
	token := security.Token{
		AccessToken:  tokenStr,
		TokenType:    s.TokenType,
		RefreshToken: "",
		Expiry:       time.Time{},
		ExpiresIn:    0,
		Claims:       nil,
	}
	jwtToken, err := s.Parser.ParseWithClaims(tokenStr, &Claims{}, s.parseToken)
	if err != nil || jwtToken == nil || !jwtToken.Valid {
		return security.Token{}, ErrInvalidToken
	}

	if claims, ok := jwtToken.Claims.(*Claims); ok {
		token.Claims = (*security.Claims)(claims)
	} else {
		return security.Token{}, ErrInvalidToken
	}
	return token, nil
}

// parseToken parses the given token string and returns the claims.
func (s Serialize) parseToken(token *jwt.Token) (any, error) {
	for _, keyFunc := range s.KeyFns {
		key, err := keyFunc(token)
		if err == nil {
			return key, nil
		}
	}
	return nil, ErrInvalidToken
}

func NewTokenSerializer(ts ...SerializeSetting) security.TokenSerializer {
	serialize := settings.Apply(&Serialize{
		Domain:    defaultDomain,
		Expired:   defaultExpired,
		TokenType: defaultTokenType,
		Method:    defaultMethod,
		Key:       []byte(defaultKey),
		OldKey:    nil,
	}, ts)

	if serialize.Parser == nil {
		serialize.Parser = jwt.NewParser()
	}

	serialize.KeyFns = append(serialize.KeyFns, func(t *jwt.Token) (any, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, ErrInvalidToken
		}
		return serialize.Key, nil
	})

	if serialize.OldKey != nil {
		serialize.KeyFns = append(serialize.KeyFns, func(t *jwt.Token) (any, error) {
			if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, ErrInvalidToken
			}
			return serialize.OldKey, nil
		})
	}

	return serialize
}
