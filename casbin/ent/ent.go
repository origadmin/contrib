// Copyright (c) 2024 OrigAdmin. All rights reserved.

// Package ent is the casbin ent adapter package
package ent

import (
	adapter "github.com/origadmin/ent-adapter"
)

var (
	NewAdapter           = adapter.NewAdapter
	NewAdapterWithClient = adapter.NewAdapterWithClient
	DefaultDatabase      = adapter.DefaultDatabase
	DefaultTableName     = adapter.DefaultTableName
)

type (
	Option  = adapter.Option
	Filter  = adapter.Filter
	Adapter = adapter.Adapter
)
