/*
 * Copyright (c) 2024 OrigAdmin. All rights reserved.
 */

// Package jwt provides functions for generating and validating JWT tokens.
package jwt

import (
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func WithParser(parser *jwt.Parser) SerializeSetting {
	return func(o *Serialize) {
		o.Parser = parser
	}
}

func WithDomain(domain string) SerializeSetting {
	return func(o *Serialize) {
		o.Domain = domain
	}
}

func WithTokenType(tokenType string) SerializeSetting {
	return func(o *Serialize) {
		o.TokenType = tokenType
	}
}

func WithExpired(expired int) SerializeSetting {
	return func(o *Serialize) {
		o.Expired = time.Duration(expired)
	}
}

func WithKey(key string, keys ...string) SerializeSetting {
	return func(o *Serialize) {
		o.Key = []byte(key)
		if len(keys) > 0 {
			o.Key = []byte(keys[0])
		}
	}
}

func WithKeyFns(keyFns ...func(*jwt.Token) (any, error)) SerializeSetting {
	return func(o *Serialize) {
		o.KeyFns = keyFns
	}
}

func WithSigningMethod(method jwt.SigningMethod) SerializeSetting {
	return func(o *Serialize) {
		o.Method = method
	}
}
