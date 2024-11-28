/*
 * Copyright (c) 2024 OrigAdmin. All rights reserved.
 */

// Package pagination implements the functions, types, and interfaces for the module.
package pagination

import (
	"entgo.io/ent/dialect/sql"
)

func OrdersBy(fields []string, opts ...sql.OrderTermOption) []func(*sql.Selector) {
	var orders []func(selector *sql.Selector)
	for _, field := range fields {
		orders = append(orders, sql.OrderByField(field, opts...).ToFunc())
	}
	return orders
}
