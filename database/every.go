// Copyright (c) 2024 OrigAdmin. All rights reserved.

//go:build !sqlite3 && !mysql && !postgres

// Package database is the database client wrapper
package database

import (
	_ "github.com/go-sql-driver/mysql"
	_ "github.com/lib/pq"
	_ "github.com/sqlite3ent/sqlite3"
)

// Every ...
type Every struct{}
