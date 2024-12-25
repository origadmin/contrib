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

// OpenDB opens a database connection using the provided configuration
func OpenDB(cfg *configv1.Data_Database) (*entsql.Driver, error) {
	// Open a database connection using the provided dialect and source
	db, err := sql.Open(cfg.Dialect, cfg.Source)
	if err != nil {
		// Return an error if the connection fails
		return nil, err
	}
	// Open an ent database connection using the provided dialect and database connection
	entdb := entsql.OpenDB(cfg.Dialect, db)
	// Return the ent database connection
	return entdb, nil
}

// OpenSqlDB opens a database connection using the provided dialect and database connection
func OpenSqlDB(dialect string, db *sql.DB) *entsql.Driver {
	// Open an ent database connection using the provided dialect and database connection
	return entsql.OpenDB(dialect, db)
}
