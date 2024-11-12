package ent

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"entgo.io/ent/dialect/sql"
	"github.com/origadmin/toolkits/orm"
)

// DB is the database client.
type DB struct {
	config orm.Config
	once   *sync.Once
	drv    *sql.Driver
}

func open(config orm.Config) (*DB, error) {
	var drv *sql.Driver
	var err error
	dialect := strings.ToLower(config.Dialect)
	switch dialect {
	case "mysql", "tidb":
		dialect = "mysql"
	case "postgres":
	case "sqlite3":
		_ = os.MkdirAll(filepath.Dir(config.DSN), os.ModePerm)
	default:
		err = fmt.Errorf("unsupported database type: %s", config.Dialect)
	}

	drv, err = sql.Open(dialect, config.DSN)
	if err != nil {
		return nil, fmt.Errorf("failed to open database: %v", err)
	}

	sqlDB := drv.DB()
	sqlDB.SetMaxIdleConns(config.MaxIdleConns)
	sqlDB.SetMaxOpenConns(config.MaxOpenConns)
	sqlDB.SetConnMaxLifetime(time.Duration(config.MaxLifetime) * time.Second)
	sqlDB.SetConnMaxIdleTime(time.Duration(config.MaxIdleTime) * time.Second)

	return &DB{
		config: config,
		drv:    drv,
	}, nil
}

// Close closes the database connection.
func (db *DB) Close() error {
	var err error
	if db.once != nil {
		db.once.Do(func() {
			err = db.drv.Close()
		})
		return err
	}
	return db.drv.Close()
}

// Before executes the hooks before the database connection.
func (db *DB) Before(ctx context.Context, fns ...Before) error {
	for i := range fns {
		err := fns[i](ctx, db.drv)
		if err != nil {
			return err
		}
	}
	return nil
}

// After executes the hooks after the database connection.
func (db *DB) After(ctx context.Context, fns ...After) error {
	for i := range fns {
		err := fns[i](ctx, db.drv)
		if err != nil {
			return err
		}
	}
	return nil
}

// Connector returns a new database connector.
func (db *DB) Connector(builder Builder) orm.Connector {
	return connector(db, builder)
}

// Driver returns the underlying database driver.
func (db *DB) Driver() *sql.Driver {
	return db.drv
}

// New creates a new database instance.
func New(config orm.Config) (*DB, error) {
	if config.Context == nil {
		config.Context = context.Background()
	}

	return open(config)
}
