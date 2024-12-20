/*
 * Copyright (c) 2024 OrigAdmin. All rights reserved.
 */

// Package database implements the functions, types, and interfaces for the module.
package database

import (
	"database/sql"
	"time"

	configv1 "github.com/origadmin/runtime/gen/go/config/v1"
	"github.com/origadmin/toolkits/errors"

	"github.com/origadmin/contrib/database/internal/mysql"
)

func Open(database *configv1.Data_Database) (*sql.DB, error) {
	if database == nil {
		return nil, errors.New("database is nil")
	}
	switch database.Driver {
	case "mysql":
		err := mysql.CreateDatabase(database.Source, "")
		if err != nil {
			return nil, errors.Wrap(err, "create database error")
		}
		break
	case "pgx":
		database.Driver = "postgres"
		break
	default:

	}
	db, err := sql.Open(database.Driver, database.Source)
	if err != nil {
		return nil, errors.Wrap(err, "open database error")
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
	return db, nil
}
