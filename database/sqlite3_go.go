// Copyright (c) 2024 OrigAdmin. All rights reserved.

//go:build sqlite3 && !cgo

// Package database is the database client wrapper
package database

import (
	_ "github.com/sqlite3ent/sqlite3"
)

type SQLite3Go struct{}
