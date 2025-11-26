/* * Copyright (c) 2024 OrigAdmin. All rights reserved. */

// Package jwt implements the functions, types, and interfaces for module.
package jwt

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"time"

	jwtv5 "github.com/golang-jwt/jwt/v5"

	"github.com/origadmin/runtime/extension/optionutil"

	jwtv1 "github.com/origadmin/contrib/api/gen/go/security/authn/jwt/v1"
	securitycache "github.com/origadmin/contrib/security/authn/cache" // Updated import path
	"github.com/origadmin/runtime/interfaces/options"
)

// Option holds the configuration options for the JWT authenticator.
type Option struct {
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
}

// Apply merges the JWT configuration from the proto message into the Option struct.
func (o *Option) Apply(cfg *jwtv1.Config) error {
	if cfg == nil {
		return nil // Nothing to apply
	}
	// Configure signing method and key function from the config file.
	if cfg.SigningMethod != "" && cfg.SigningKey != "" {
		signingMethod, keyFunc, err := configureKeys(cfg)
		if err != nil {
			return err
		}
		o.signingMethod = signingMethod
		o.keyFunc = keyFunc
	} else if o.signingMethod == nil || o.keyFunc == nil {
		return fmt.Errorf("JWT signing method and key function must be configured")
	}

	// Set Issuer
	if cfg.Issuer != "" {
		o.issuer = cfg.Issuer
	} else if o.issuer == "" {
		o.issuer = defaultIssuer
	}

	// Set Audience
	if len(cfg.Audience) > 0 {
		o.audience = cfg.Audience
	}

	// Set token TTLs, prioritizing config, then programmatic options, then default.
	if cfg.AccessTokenLifetime > 0 {
		o.accessTokenLifetime = time.Duration(cfg.AccessTokenLifetime) * time.Second
	} else if o.accessTokenLifetime == 0 {
		o.accessTokenLifetime = defaultAccessTokenTTL
	}

	if cfg.RefreshTokenLifetime > 0 {
		o.refreshTokenLifetime = time.Duration(cfg.RefreshTokenLifetime) * time.Second
	} else if o.refreshTokenLifetime == 0 {
		o.refreshTokenLifetime = defaultRefreshTokenTTL
	}

	return nil
}

// configureKeys determines the signing method and key function from the config.
func configureKeys(cfg *jwtv1.Config) (jwtv5.SigningMethod, jwtv5.Keyfunc, error) {
	alg := GetSigningMethod(cfg.SigningMethod)
	if alg == nil {
		return nil, nil, fmt.Errorf("unsupported JWT algorithm: %s", cfg.SigningMethod)
	}

	keyData := cfg.SigningKey
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

// GetSigningMethod returns the signing method for a given algorithm string.
func GetSigningMethod(algorithm string) jwtv5.SigningMethod {
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
func WithExtraClaims(extras map[string]string) options.Option {
	return optionutil.Update(func(o *Option) {
		o.extraClaims = extras
	})
}

// WithCache returns an options.Option that sets token cache.
func WithCache(cache securityToken.CacheStorage) options.Option { // Use securityToken.CacheStorage
	return optionutil.Update(func(o *Option) {
		o.cache = cache
	})
}

// WithSigningMethod returns an options.Option that sets JWT signing method.
func WithSigningMethod(signingMethod jwtv5.SigningMethod) options.Option {
	return optionutil.Update(func(o *Option) {
		o.signingMethod = signingMethod
	})
}

// WithKeyFunc returns an options.Option that sets key function.
func WithKeyFunc(keyFunc func(token *jwtv5.Token) (any, error)) options.Option {
	return optionutil.Update(func(o *Option) {
		o.keyFunc = keyFunc
	})
}

// WithAccessTokenLifetime returns an options.Option that sets access token expiration.
func WithAccessTokenLifetime(d time.Duration) options.Option {
	return optionutil.Update(func(o *Option) {
		o.accessTokenLifetime = d
	})
}

// WithRefreshTokenLifetime returns an options.Option that sets refresh token expiration.
func WithRefreshTokenLifetime(d time.Duration) options.Option {
	return optionutil.Update(func(o *Option) {
		o.refreshTokenLifetime = d
	})
}

// WithIssuer returns an options.Option that sets JWT issuer.
func WithIssuer(issuer string) options.Option {
	return optionutil.Update(func(o *Option) {
		o.issuer = issuer
	})
}

// WithAudience returns an options.Option that sets JWT audience.
func WithAudience(audience []string) options.Option {
	return optionutil.Update(func(o *Option) {
		o.audience = audience
	})
}

// WithClock provides a function to return the current time, useful for testing.
func WithClock(c func() time.Time) options.Option {
	return optionutil.Update(func(o *Option) {
		o.clock = c
	})
}

// WithGenerateID provides a function to generate unique IDs (e.g., for 'jti' claims).
func WithGenerateID(g func() string) options.Option {
	return optionutil.Update(func(o *Option) {
		o.generateID = g
	})
}

// FromOptions creates a new Option struct from a slice of option functions.
func FromOptions(opts ...options.Option) *Option {
	return optionutil.NewT[Option](opts...)
}
