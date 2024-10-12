// Copyright (c) 2024 OrigAdmin. All rights reserved.

//go:build mysql

// Package support is the database client wrapper
package support

import (
	_ "github.com/go-sql-driver/mysql"
)

type MySQL struct{}
