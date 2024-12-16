/*
 * Copyright (c) 2024 OrigAdmin. All rights reserved.
 */

// Package jwt implements the functions, types, and interfaces for the module.
package jwt

import (
	jwtv5 "github.com/golang-jwt/jwt/v5"
	"github.com/origadmin/toolkits/errors"
	"github.com/origadmin/toolkits/security"
)

// Setting is a function type for setting the Authenticator.
type Setting = func(*Authenticator)

// GetKeyFunc returns a function that retrieves the key for a given token.
// The returned function takes a jwtv5.Token as an argument and returns the key as a string.
func GetKeyFunc(key string) func(token *jwtv5.Token) (any, error) {
	// Return a function that checks if the token's algorithm is empty.
	// If it is, return an error. Otherwise, return the key.
	return func(token *jwtv5.Token) (any, error) {
		if token.Method.Alg() == "" {
			// Return an error if the token's algorithm is empty.
			return nil, ErrInvalidToken
		}
		// Return the key if the token's algorithm is not empty.
		return key, nil
	}
}

// GetKeyFuncWithAlg returns a function that retrieves the key for a given token
// with a specific algorithm.
// The returned function takes a jwtv5.Token as an argument and returns the key as a byte slice.
func GetKeyFuncWithAlg(alg, key string) func(token *jwtv5.Token) (any, error) {
	// Return a function that checks if the token's algorithm matches the provided algorithm.
	// If it does not, return an error. Otherwise, return the key as a byte slice.
	return func(token *jwtv5.Token) (any, error) {
		if token.Method.Alg() == "" || alg != token.Method.Alg() {
			// Return an error if the token's algorithm does not match the provided algorithm.
			return nil, ErrInvalidToken
		}
		// jwtv5 requires the key to be a byte slice.
		return []byte(key), nil
	}
}

// GetSigningMethodFromAlg returns the signing method for a given algorithm.
func GetSigningMethodFromAlg(algorithm string) jwtv5.SigningMethod {
	// Use a switch statement to map the algorithm to its corresponding signing method.
	switch algorithm {
	case "HS256":
		// Return the signing method for HS256.
		return jwtv5.SigningMethodHS256
	case "HS384":
		// Return the signing method for HS384.
		return jwtv5.SigningMethodHS384
	case "HS512":
		// Return the signing method for HS512.
		return jwtv5.SigningMethodHS512
	case "RS256":
		// Return the signing method for RS256.
		return jwtv5.SigningMethodRS256
	case "RS384":
		// Return the signing method for RS384.
		return jwtv5.SigningMethodRS384
	case "RS512":
		// Return the signing method for RS512.
		return jwtv5.SigningMethodRS512
	case "ES256":
		// Return the signing method for ES256.
		return jwtv5.SigningMethodES256
	case "ES384":
		// Return the signing method for ES384.
		return jwtv5.SigningMethodES384
	case "ES512":
		// Return the signing method for ES512.
		return jwtv5.SigningMethodES512
	case "EdDSA":
		// Return the signing method for EdDSA.
		return jwtv5.SigningMethodEdDSA
	default:
		// Return nil if the algorithm is not recognized.
		return nil
	}
}

// WithExtraKeys returns a Setting function that sets the extra keys for an Authenticator.
func WithExtraKeys(extraKeys ...string) Setting {
	// Return a function that sets the extra keys for an Authenticator.
	return func(auth *Authenticator) {
		// Set the extra keys for the Authenticator.
		auth.extraKeys = extraKeys
	}
}

// WithCache returns a Setting function that sets the token cache service for an Authenticator.
func WithCache(cache security.TokenCacheService) Setting {
	// Return a function that sets the token cache service for an Authenticator.
	return func(auth *Authenticator) {
		// Set the token cache service for the Authenticator.
		auth.cache = cache
	}
}

// WithScheme returns a Setting function that sets the scheme for an Authenticator.
func WithScheme(scheme security.Scheme) Setting {
	// Return a function that sets the scheme for an Authenticator.
	return func(auth *Authenticator) {
		// Set the scheme for the Authenticator.
		auth.schemeType = scheme
	}
}

// WithScoped returns a Setting function that sets the scoped flag for an Authenticator.
// The scoped flag determines whether the Authenticator should use scoped tokens.
func WithScoped(scoped bool) Setting {
	// Return a function that sets the scoped flag for an Authenticator.
	return func(auth *Authenticator) {
		// Set the scoped flag for the Authenticator.
		auth.scoped = scoped
	}
}

// WithSigningMethod returns a Setting function that sets the signing method for an Authenticator.
// The signing method is used to sign and verify tokens.
func WithSigningMethod(signingMethod jwtv5.SigningMethod) Setting {
	// Return a function that sets the signing method for an Authenticator.
	return func(auth *Authenticator) {
		// Set the signing method for the Authenticator.
		auth.signingMethod = signingMethod
	}
}

// WithKeyFunc returns a Setting function that sets the key function for an Authenticator.
// The key function is used to retrieve the key for a given token.
func WithKeyFunc(keyFunc func(token *jwtv5.Token) (any, error)) Setting {
	// Return a function that sets the key function for an Authenticator.
	return func(auth *Authenticator) {
		// Set the key function for the Authenticator.
		auth.keyFunc = keyFunc
	}
}

func getSigningMethodAndKeyFunc(algorithm string, signingKey string) (jwtv5.SigningMethod, func(*jwtv5.Token) (any, error), error) {
	signingMethod := GetSigningMethodFromAlg(algorithm)
	if signingMethod == nil {
		return nil, nil, errors.New("invalid signing method")
	}

	keyFunc := GetKeyFuncWithAlg(algorithm, signingKey)
	if keyFunc == nil {
		return nil, nil, errors.New("invalid key function")
	}

	return signingMethod, keyFunc, nil
}
