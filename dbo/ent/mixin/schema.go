/*
 * Copyright (c) 2024 OrigAdmin. All rights reserved.
 */

// Package mixin is the mixin package
package mixin

import (
	"time"

	"entgo.io/ent"
	"entgo.io/ent/dialect"
	"entgo.io/ent/schema/field"
)

// ZeroTime represents the zero value for time.Time.
var ZeroTime = time.Time{}

// Index returns a unique integer field.
func Index(name string) ent.Field {
	// Create a unique integer field with the given name.
	return field.Int(name).Unique()
}

// OptionalID returns an optional string field with a maximum length of 36 characters.
func OptionalID(name string) ent.Field {
	// Create an optional string field with the given name and maximum length.
	return field.String(name).
		MaxLen(36).
		Optional()
}

// PrimaryID returns a unique string field with a maximum length of 36 characters.
func PrimaryID(name string) ent.Field {
	// Create a unique string field with the given name and maximum length.
	return field.String(name).
		MaxLen(36).
		Unique().
		Immutable()
}

// Time returns a time field with a default value of ZeroTime and a custom schema type for MySQL.
func Time(name string) ent.Field {
	// Create a time field with the given name and a default value of ZeroTime.
	return field.Time(name).
		// Set the default value of the field to ZeroTime.
		Default(func() time.Time {
			return ZeroTime
		}).
		// Set the schema type of the field to "datetime" for MySQL dialect.
		SchemaType(map[string]string{
			dialect.MySQL: "datetime",
		})
}
