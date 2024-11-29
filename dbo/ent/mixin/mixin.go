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
		field.String("id").MaxLen(36).Unique(),
	}
}

// Indexes of the mixin.
func (ID) Indexes() []ent.Index {
	return []ent.Index{}
}

// Origin schema to include control and time fields.
type Origin struct {
	mixin.Schema
}

// Fields of the mixin.
func (Origin) Fields() []ent.Field {
	return []ent.Field{
		field.String("created_by").Default(""),
		field.String("updated_by").Default(""),
	}
}

// Indexes of the mixin.
func (Origin) Indexes() []ent.Index {
	return []ent.Index{
		index.Fields("created_by"),
		index.Fields("updated_by"),
	}
}

// CreatedSchema schema to include control and time fields.
type CreatedSchema struct {
	mixin.Schema
}

// Fields of the mixin.
func (CreatedSchema) Fields() []ent.Field {
	return []ent.Field{
		field.Time("created_at").
			Default(time.Now).
			Immutable(),
	}
}

// Indexes of the mixin.
func (CreatedSchema) Indexes() []ent.Index {
	return []ent.Index{
		index.Fields("created_at"),
	}
}

// UpdatedSchema schema to include control and time fields.
type UpdatedSchema struct {
	mixin.Schema
}

// Fields of the mixin.
func (UpdatedSchema) Fields() []ent.Field {
	return []ent.Field{
		field.Time("update_time").
			Default(time.Now).
			UpdateDefault(time.Now),
	}
}

// Indexes of the mixin.
func (UpdatedSchema) Indexes() []ent.Index {
	return []ent.Index{
		index.Fields("update_time"),
	}
}

// DeletedSchema schema to include control and time fields.
type DeletedSchema struct {
	mixin.Schema
}

// Fields of the Model.
func (DeletedSchema) Fields() []ent.Field {
	return []ent.Field{
		field.Time("delete_time").
			Optional().
			Nillable(),
	}
}

// Indexes of the mixin.
func (DeletedSchema) Indexes() []ent.Index {
	return []ent.Index{
		index.Fields("delete_time"),
	}
}

// SoftDeleteSchema schema to include control and time fields.
type SoftDeleteSchema = DeletedSchema
