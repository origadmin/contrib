/*
 * Copyright (c) 2024 OrigAdmin. All rights reserved.
 */

// Package mixin implements the functions, types, and interfaces for the module.
package mixin

import (
	"context"
	"time"

	"entgo.io/ent"
	"entgo.io/ent/schema/field"
	"entgo.io/ent/schema/index"
	"entgo.io/ent/schema/mixin"
)

type IDGenerator interface {
	OP(name string) ent.Field
	FK(name string) ent.Field
	PK(name string, fn ...any) ent.Field
}

// Audit schema to include control and time fields.
type Audit struct {
	mixin.Schema
	CommentKey string
}

// Fields of the mixin.
func (Audit) Fields() []ent.Field {
	auditCreate := _id
	auditCreate.Key = "create_author"
	auditCreate.CommentKey = "entity.create_author.field.comment"
	auditCreate.UseDefault = true
	auditCreate.Optional = true
	auditUpdate := _id
	auditUpdate.Key = "update_author"
	auditUpdate.CommentKey = "entity.update_author.field.comment"
	auditUpdate.UseDefault = true
	auditUpdate.Optional = true
	return []ent.Field{
		auditCreate.ToField(),
		auditUpdate.ToField(),
	}
}

// Indexes of the mixin.
func (Audit) Indexes() []ent.Index {
	return []ent.Index{
		index.Fields("create_author"),
		index.Fields("update_author"),
	}
}

// ManagerSchema schema to include control and time fields.
type ManagerSchema struct {
	mixin.Schema
	I18nText func(key string) string
}

// Fields of the Model.
func (s ManagerSchema) Fields() []ent.Field {
	manager := _id
	manager.Key = "manager_id"
	manager.CommentKey = "entity.manager_id.field.comment"
	manager.Optional = true
	manager.UseDefault = true
	managerName := ""
	if s.I18nText != nil {
		managerName = s.I18nText("entity.manager_name.field.comment")
	}
	return []ent.Field{
		manager.ToField(),
		field.String("manager_name").
			Comment(managerName).
			Default(""),
	}
}

// Indexes of the mixin.
func (ManagerSchema) Indexes() []ent.Index {
	return []ent.Index{
		index.Fields("manager_id"),
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
	I18nText func(key string) string
}

// Fields of the mixin.
func (s CreateSchema) Fields() []ent.Field {
	i18n := ""
	if s.I18nText != nil {
		i18n = s.I18nText("entity.create_time.field.comment")
	}
	return []ent.Field{
		field.Time("create_time").
			Comment(i18n).
			Default(time.Now).
			Immutable(),
	}
}

// Indexes of the mixin.
func (CreateSchema) Indexes() []ent.Index {
	return []ent.Index{
		index.Fields("create_time"),
	}
}

// UpdateSchema schema to include control and time fields.
type UpdateSchema struct {
	mixin.Schema
	I18nText func(key string) string
}

// Fields of the mixin.
func (s UpdateSchema) Fields() []ent.Field {
	i18n := ""
	if s.I18nText != nil {
		i18n = s.I18nText("entity.update_time.field.comment")
	}
	return []ent.Field{
		field.Time("update_time").
			Comment(i18n).
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
	I18nText func(key string) string
}

// Fields of the Model.
func (s DeleteSchema) Fields() []ent.Field {
	i18n := ""
	if s.I18nText != nil {
		i18n = s.I18nText("entity.update_time.field.comment")
	}
	return []ent.Field{
		field.Time("delete_time").
			Comment(i18n).
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

var (
	ModelMixin = []ent.Mixin{
		_id,
		CreateSchema{},
		UpdateSchema{},
	}
	AuditModelMixin = []ent.Mixin{
		_id,
		Audit{},
		CreateSchema{},
		UpdateSchema{},
	}
)

type softDeleteKey struct{}

// SkipSoftDelete returns a new context that skips the soft-delete interceptor/mutators.
func SkipSoftDelete(parent context.Context) context.Context {
	return context.WithValue(parent, softDeleteKey{}, true)
}

func IsSkipSoftDelete(ctx context.Context) bool {
	v, _ := ctx.Value(softDeleteKey{}).(bool)
	return v
}
