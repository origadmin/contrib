// Copyright (c) 2024 OrigAdmin. All rights reserved.

//go:build postgres

// Package database is the database client wrapper
package database

import (
	_ "github.com/lib/pq"
)

type Postgres struct{}
