// Copyright (c) 2024 OrigAdmin. All rights reserved.

//go:build sqlite3 && cgo

// Package support is the database client wrapper
package support

import (
	_ "github.com/mattn/go-sqlite3"
)

type SQLite3Cgo struct{}
