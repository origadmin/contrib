/*
 * Copyright (c) 2024 OrigAdmin. All rights reserved.
 */

package jwt

import (
	"github.com/origadmin/toolkits/errors"
)

var (
	ErrInvalidToken           = errors.New("invalid token")
	ErrMissingSigningKey      = errors.New("signing key is missing")
	ErrUnsupportedSigningMethod = errors.New("unsupported signing method")
)
