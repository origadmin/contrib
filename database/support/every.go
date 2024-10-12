// Copyright (c) 2024 OrigAdmin. All rights reserved.

//go:build !sqlite3 && !mysql && !postgres

// Package support is the database client wrapper
package support

import (
	_ "github.com/go-sql-driver/mysql"
	_ "github.com/lib/pq"
	_ "github.com/sqlite3ent/sqlite3"
)

// Every ...
type Every struct{}
