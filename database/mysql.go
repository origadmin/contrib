// Copyright (c) 2024 OrigAdmin. All rights reserved.

//go:build mysql

// Package database is the database client wrapper
package database

import (
	_ "github.com/go-sql-driver/mysql"
)

type MySQL struct{}
