/*
 * Copyright (c) 2024 OrigAdmin. All rights reserved.
 */

// Package ent implements the functions, types, and interfaces for the module.
package ent

import (
	"database/sql"
	"time"

	entsql "entgo.io/ent/dialect/sql"
	configv1 "github.com/origadmin/runtime/gen/go/config/v1"
	"github.com/origadmin/toolkits/errors"
)

func OpenDB(database *configv1.Data_Database) (*entsql.Driver, error) {
	db, err := sql.Open(database.Dialect, database.Source)
	if err != nil {
		return nil, errors.Wrap(err, "database: open database error")
	}
	if database.MaxIdleConnections > 0 {
		db.SetMaxIdleConns(int(database.MaxIdleConnections))
	}
	if database.MaxOpenConnections > 0 {
		db.SetMaxOpenConns(int(database.MaxOpenConnections))
	}
	if t := database.ConnectionMaxLifetime; t > 0 {
		db.SetConnMaxLifetime(time.Duration(t))
	}
	if t := database.ConnectionMaxIdleTime; t > 0 {
		db.SetConnMaxIdleTime(time.Duration(t))
	}
	return OpenSqlDB(database.Dialect, db), nil
}

func OpenSqlDB(dialect string, db *sql.DB) *entsql.Driver {
	return entsql.OpenDB(dialect, db)
}
