package ent

import (
	"context"

	"entgo.io/ent/dialect/sql"
	"github.com/origadmin/toolkits/orm"
)

type conn struct {
	db      *DB
	builder func(driver *sql.Driver, config orm.Config) (any, error)
}

// Open builds DB instances.
func (c *conn) Open(config orm.Config) (any, error) {
	return c.builder(c.db.drv, config)
}

// Before executes the given functions before opening the database.
func (c *conn) Before(ctx context.Context, funcs ...Before) error {
	for _, fn := range funcs {
		err := fn(ctx, c.db.drv)
		if err != nil {
			return err
		}
	}
	return nil
}

// After executes the given functions after opening the database.
func (c *conn) After(ctx context.Context, funcs ...After) error {
	for _, fn := range funcs {
		err := fn(ctx, c.db.drv)
		if err != nil {
			return err
		}
	}
	return nil
}

// Close closes the database connection.
func (c *conn) Close() error {
	return c.db.Close()
}

// connector builds DB instances.
func connector(db *DB, builder Builder) *conn {
	return &conn{
		db:      db,
		builder: builder,
	}
}
