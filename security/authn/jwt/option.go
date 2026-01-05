/*
 * Copyright (c) 2024 OrigAdmin. All rights reserved.
 */

// Package jwt implements the functions, types, and interfaces for module.
package jwt

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"time"

	jwtv5 "github.com/golang-jwt/jwt/v5"

	securitycache "github.com/origadmin/contrib/security/authn/cache"
	"github.com/origadmin/runtime/extensions/optionutil"
	"github.com/origadmin/runtime/interfaces/options"
	"github.com/origadmin/runtime/log"
)

const (
	// DefaultIssuer is the default issuer for JWT tokens.
	DefaultIssuer = "origadmin"
	// DefaultAccessTokenTTL is the default time-to-live for access tokens.
	DefaultAccessTokenTTL = 2 * time.Hour
	// DefaultRefreshTokenTTL is the default time-to-live for refresh tokens.
	DefaultRefreshTokenTTL = 7 * 24 * time.Hour
)

// Options holds the configuration options for the JWT authenticator.
type Options struct {
	cache                securitycache.Cache
	signingMethod        jwtv5.SigningMethod
	keyFunc              jwtv5.Keyfunc
	accessTokenLifetime  time.Duration
	refreshTokenLifetime time.Duration
	issuer               string
	audience             []string
	extraClaims          map[string]string
	clock                func() time.Time
	generateID           func() string
	Logger               log.Logger
}

// Option is a functional option type for configuring the JWT authenticator.
type Option = options.Option

// configureKeys determines the signing method and key function from the provided algorithm and key data.
func configureKeys(algorithm, keyData string) (jwtv5.SigningMethod, jwtv5.Keyfunc, error) {
	alg := getSigningMethod(algorithm)
	if alg == nil {
		return nil, nil, fmt.Errorf("unsupported JWT algorithm: %s", algorithm)
	}

	if keyData == "" {
		return nil, nil, fmt.Errorf("signing key is missing")
	}

	switch method := alg.(type) {
	case *jwtv5.SigningMethodHMAC:
		key := []byte(keyData)
		return method, func(t *jwtv5.Token) (interface{}, error) { return key, nil }, nil
	case *jwtv5.SigningMethodRSA, *jwtv5.SigningMethodRSAPSS:
		pubKey, err := parseRSAPublicKey(keyData)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to parse RSA public key: %w", err)
		}
		privKey, err := parseRSAPrivateKey(keyData)
		if err != nil {
			// If private key parsing fails, assume we only have public key for verification.
			return method, func(t *jwtv5.Token) (interface{}, error) { return pubKey, nil }, nil
		}
		// Return private key for signing, public key for verification.
		return method, func(t *jwtv5.Token) (interface{}, error) {
			if _, ok := t.Method.(*jwtv5.SigningMethodRSA); ok {
				return privKey, nil
			}
			return pubKey, nil
		}, nil
	default:
		return nil, nil, fmt.Errorf("unsupported signing method type: %T", method)
	}
}

// parseRSAPublicKey parses a PEM-encoded RSA public key.
func parseRSAPublicKey(keyData string) (*rsa.PublicKey, error) {
	block, _ := pem.Decode([]byte(keyData))
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block containing public key")
	}

	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		if key, errPkcs1 := x509.ParsePKCS1PublicKey(block.Bytes); errPkcs1 == nil {
			return key, nil
		}
		return nil, fmt.Errorf("failed to parse DER encoded public key: %w", err)
	}

	rsaKey, ok := pub.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("key is not an RSA public key")
	}
	return rsaKey, nil
}

// parseRSAPrivateKey parses a PEM-encoded RSA private key.
func parseRSAPrivateKey(keyData string) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode([]byte(keyData))
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block containing private key")
	}

	priv, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		if key, errPkcs8 := x509.ParsePKCS8PrivateKey(block.Bytes); errPkcs8 == nil {
			if rsaKey, ok := key.(*rsa.PrivateKey); ok {
				return rsaKey, nil
			}
		}
		return nil, fmt.Errorf("failed to parse DER encoded private key: %w", err)
	}
	return priv, nil
}

// getSigningMethod returns the signing method for a given algorithm string.
func getSigningMethod(algorithm string) jwtv5.SigningMethod {
	switch algorithm {
	case "HS256":
		return jwtv5.SigningMethodHS256
	case "HS384":
		return jwtv5.SigningMethodHS384
	case "HS512":
		return jwtv5.SigningMethodHS512
	case "RS256":
		return jwtv5.SigningMethodRS256
	case "RS384":
		return jwtv5.SigningMethodRS384
	case "RS512":
		return jwtv5.SigningMethodRS512
	case "ES256":
		return jwtv5.SigningMethodES256
	case "ES384":
		return jwtv5.SigningMethodES384
	case "ES512":
		return jwtv5.SigningMethodES512
	case "EdDSA":
		return jwtv5.SigningMethodEdDSA
	default:
		return nil
	}
}

// WithExtraClaims returns an options.Option that sets extra claims.
func WithExtraClaims(extras map[string]string) Option {
	return optionutil.Update(func(o *Options) {
		o.extraClaims = extras
	})
}

// WithCache returns an options.Option that sets token cache.
func WithCache(cache securitycache.Cache) Option {
	return optionutil.Update(func(o *Options) {
		o.cache = cache
	})
}

// WithSigningMethod returns an options.Option that sets JWT signing method.
func WithSigningMethod(signingMethod jwtv5.SigningMethod) Option {
	return optionutil.Update(func(o *Options) {
		o.signingMethod = signingMethod
	})
}

// WithKeyFunc returns an options.Option that sets key function.
func WithKeyFunc(keyFunc func(token *jwtv5.Token) (any, error)) Option {
	return optionutil.Update(func(o *Options) {
		o.keyFunc = keyFunc
	})
}

// WithSigningKey sets the JWT signing method and key function from algorithm and key data strings.
// This is a convenience option for common use cases.
func WithSigningKey(algorithm, keyData string) Option {
	return optionutil.Update(func(o *Options) {
		signingMethod, keyFunc, err := configureKeys(algorithm, keyData)
		if err != nil {
			panic(fmt.Errorf("failed to configure signing key with algorithm '%s': %w", algorithm, err))
		}
		o.signingMethod = signingMethod
		o.keyFunc = keyFunc
	})
}

// WithAccessTokenLifetime returns an options.Option that sets access token expiration.
func WithAccessTokenLifetime(d time.Duration) Option {
	return optionutil.Update(func(o *Options) {
		o.accessTokenLifetime = d
	})
}

// WithRefreshTokenLifetime returns an options.Option that sets refresh token expiration.
func WithRefreshTokenLifetime(d time.Duration) Option {
	return optionutil.Update(func(o *Options) {
		o.refreshTokenLifetime = d
	})
}

// WithIssuer returns an options.Option that sets JWT issuer.
func WithIssuer(issuer string) Option {
	return optionutil.Update(func(o *Options) {
		o.issuer = issuer
	})
}

// WithAudience returns an options.Option that sets JWT audience.
func WithAudience(audience []string) Option {
	return optionutil.Update(func(o *Options) {
		o.audience = audience
	})
}

// WithClock provides a function to return the current time, useful for testing.
func WithClock(c func() time.Time) Option {
	return optionutil.Update(func(o *Options) {
		o.clock = c
	})
}

// WithGenerateID provides a function to generate unique IDs (e.g., for 'jti' claims).
func WithGenerateID(g func() string) Option {
	return optionutil.Update(func(o *Options) {
		o.generateID = g
	})
}

// WithLogger sets the logger for the authenticator.
func WithLogger(logger log.Logger) Option {
	return log.WithLogger(logger)
}

// FromOptions creates a new Options struct from a slice of option functions.
func FromOptions(opts ...Option) *Options {
	o := &Options{}
	optionutil.Apply(o, opts...)

	// CORRECTED: Pass the slice directly without the variadic '...' operator.
	o.Logger = log.FromOptions(opts)

	return o
}
