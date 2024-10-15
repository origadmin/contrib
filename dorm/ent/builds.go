package ent

import (
	"context"

	"entgo.io/ent/dialect/sql"

	"github.com/origadmin/toolkits/orm"
)

// Builder is a builder function that returns a driver.
type Builder func(drv *sql.Driver, config orm.Config) (any, error)

// Before is a hook that is executed before opening a database connection.
type Before func(ctx context.Context, drv *sql.Driver) (err error)

// After is a hook that is executed after closing a database connection.
type After func(ctx context.Context, drv *sql.Driver) (err error)
