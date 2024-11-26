/*
 * Copyright (c) 2024 OrigAdmin. All rights reserved.
 */

// Package database implements the functions, types, and interfaces for the module.
package database

import (
	"database/sql"

	"github.com/origadmin/toolkits/contrib/database/internal/mysql"
)

func Open(driverName, dataSourceName string) (*sql.DB, error) {
	switch driverName {
	case "mysql":
		err := mysql.CreateDatabase(dataSourceName, "")
		if err != nil {
			return nil, err
		}
		break
	case "pgx":
		driverName = "postgres"
		break
	default:

	}
	return sql.Open(driverName, dataSourceName)
}
