// Copyright (c) 2024 OrigAdmin. All rights reserved.

//go:build postgres

// Package support is the database client wrapper
package support

import (
	_ "github.com/lib/pq"
)

type Postgres struct{}
