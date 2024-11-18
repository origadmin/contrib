{{/* The line below tells Intellij/GoLand to enable the autocompletion based *gen.Type type. */}}
{{/* gotype: entgo.io/ent/entc/gen.Type */}}


{{ define "database" }}
{{- $pkg := base $.Config.Package -}}
{{ template "header" $ }}

{{/* Additional dependencies injected to config. */}}
{{ $deps := list }}{{ with $.Config.Annotations }}{{ $deps = $.Config.Annotations.Dependencies }}{{ end }}

import (
    "context"
    "fmt"
    "entgo.io/ent/dialect/sql"
)

// Database is the client that holds all ent builders.
type Database struct {
    client *Client
}

// NewDatabase creates a new database configured with the given options.
func NewDatabase(opts ...Option) *Database {
    return &Database{client: NewClient(opts...)}
}

func (db *Database) clientDriver(ctx context.Context) dialect.Driver {
	tx := TxFromContext(ctx)
	c := db.client
	if tx != nil {
		c = tx.Client()
	}
	return c.driver
}

// Tx runs the given function f within a transaction.
func (db *Database) Tx(ctx context.Context, fn func(context.Context) error) error {
	tx := TxFromContext(ctx)
	if tx != nil {
		return fn(ctx)
	}

	return db.InTx(ctx, func(tx *Tx) error {
		return fn(NewTxContext(ctx, tx))
	})
}

// InTx runs the given function f within a transaction.
func (db *Database) InTx(ctx context.Context, fn func(tx *Tx) error) error {
	tx := TxFromContext(ctx)
	if tx != nil {
		return fn(tx)
	}
	tx, err := db.client.Tx(ctx)
	if err != nil {
		return fmt.Errorf("starting transaction: %w", err)
	}
	if err = fn(tx); err != nil {
		if txerr := tx.Rollback(); txerr != nil {
			return fmt.Errorf("rolling back transaction: %v (original error: %w)", txerr, err)
		}
		return err
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("committing transaction: %w", err)
	}
	return nil
}

// Client returns the client that holds all ent builders.
func (db *Database) Client(ctx context.Context) *Client {
	tx := TxFromContext(ctx)
	if tx != nil {
		return tx.Client()
	}
	return db.client
}

// Exec executes a query that doesn't return rows. For example, in SQL, INSERT or UPDATE.
func (db *Database) Exec(ctx context.Context, query string, args ...interface{}) (*sql.Result, error) {
	var res sql.Result
	err := db.clientDriver(ctx).Exec(ctx, query, args, &res)
	if err != nil {
		return nil, err
	}
	return &res, nil
}

// Query executes a query that returns rows, typically a SELECT in SQL.
func (db *Database) Query(ctx context.Context, query string, args ...interface{}) (*sql.Rows, error) {
	var rows sql.Rows
	err := db.clientDriver(ctx).Query(ctx, query, args, &rows)
	if err != nil {
		return nil, err
	}
	return &rows, nil
}

{{ range $n := $.Nodes }}
    {{ $client := print $n.Name "Client" }}
    // {{ $n.Name }} is the client for interacting with the {{ $n.Name }} builders.
    func (db *Database) {{ $n.Name }}(ctx context.Context) *{{ $client }} {
        return db.Client(ctx).{{ $n.Name }}
    }
{{ end }}

{{ end }}