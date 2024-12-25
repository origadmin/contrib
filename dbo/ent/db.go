/*
 * Copyright (c) 2024 OrigAdmin. All rights reserved.
 */

// Package ent implements the functions, types, and interfaces for the module.
package ent

import (
	"database/sql"

	entsql "entgo.io/ent/dialect/sql"
	configv1 "github.com/origadmin/runtime/gen/go/config/v1"
)

func OpenDB(cfg *configv1.Data_Database) (*entsql.Driver, error) {
	db, err := sql.Open(cfg.Dialect, cfg.Source)
	if err != nil {
		return nil, err
	}
	entdb := entsql.OpenDB(cfg.Dialect, db)
	return entdb, nil
}
