/*
 * Copyright (c) 2024 OrigAdmin. All rights reserved.
 */

// Package mixin is the mixin package
package mixin

import (
	"time"

	"entgo.io/ent"
	"entgo.io/ent/schema/field"
	"entgo.io/ent/schema/index"
	"entgo.io/ent/schema/mixin"
)

// ID schema to include control and time fields.
type ID struct {
	mixin.Schema
}

// Fields of the mixin.
func (ID) Fields() []ent.Field {
	return []ent.Field{
		field.String("id").
			MaxLen(36).
			Unique().
			Immutable(),
	}
}

// Indexes of the mixin.
func (ID) Indexes() []ent.Index {
	return []ent.Index{}
}

// Audit schema to include control and time fields.
type Audit struct {
	mixin.Schema
}

// Fields of the mixin.
func (Audit) Fields() []ent.Field {
	return []ent.Field{
		field.String("create_author").Default(""),
		field.String("update_author").Default(""),
	}
}

// Indexes of the mixin.
func (Audit) Indexes() []ent.Index {
	return []ent.Index{
		index.Fields("create_author"),
		index.Fields("update_author"),
	}
}

// CreateUpdateSchema schema to include control and time fields.
type CreateUpdateSchema struct {
	mixin.Schema
}

// Fields of the mixin.
func (CreateUpdateSchema) Fields() []ent.Field {
	return append(
		CreateSchema{}.Fields(),
		UpdateSchema{}.Fields()...,
	)
}

// Indexes of the mixin.
func (CreateUpdateSchema) Indexes() []ent.Index {
	return append(
		CreateSchema{}.Indexes(),
		UpdateSchema{}.Indexes()...,
	)
}

// CreateSchema schema to include control and time fields.
type CreateSchema struct {
	mixin.Schema
}

// Fields of the mixin.
func (CreateSchema) Fields() []ent.Field {
	return []ent.Field{
		field.Time("created_time").
			Default(time.Now).
			Immutable(),
	}
}

// Indexes of the mixin.
func (CreateSchema) Indexes() []ent.Index {
	return []ent.Index{
		index.Fields("created_time"),
	}
}

// UpdateSchema schema to include control and time fields.
type UpdateSchema struct {
	mixin.Schema
}

// Fields of the mixin.
func (UpdateSchema) Fields() []ent.Field {
	return []ent.Field{
		field.Time("update_time").
			Default(time.Now).
			UpdateDefault(time.Now),
	}
}

// Indexes of the mixin.
func (UpdateSchema) Indexes() []ent.Index {
	return []ent.Index{
		index.Fields("update_time"),
	}
}

// DeleteSchema schema to include control and time fields.
type DeleteSchema struct {
	mixin.Schema
}

// Fields of the Model.
func (DeleteSchema) Fields() []ent.Field {
	return []ent.Field{
		field.Time("delete_time").
			Optional().
			Nillable(),
	}
}

// Indexes of the mixin.
func (DeleteSchema) Indexes() []ent.Index {
	return []ent.Index{
		index.Fields("delete_time"),
	}
}

// SoftDeleteSchema schema to include control and time fields.
type SoftDeleteSchema = DeleteSchema
