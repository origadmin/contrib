/*
 * Copyright (c) 2024 OrigAdmin. All rights reserved.
 */

// Package mixin is the mixin package
package mixin

import (
	"entgo.io/ent"
	"entgo.io/ent/dialect/entsql"
	"entgo.io/ent/schema/field"
	"entgo.io/ent/schema/mixin"
)

type ID struct {
	mixin.Schema
	Key                  string
	CommentKey           string
	I18nText             func(key string) string
	Optional             bool
	Positive             bool
	Unique               bool
	Immutable            bool
	UseDefault           bool
	DefaultFunc          any
	UseCustomIDGenerator bool
}

func (obj ID) ToField() ent.Field {
	builder := field.Int64(obj.Key)
	if obj.UseDefault {
		builder = builder.Default(0)
	}
	if obj.Positive {
		builder = builder.Positive()
	}
	if obj.Unique {
		builder = builder.Unique()
	}
	if obj.Immutable {
		builder = builder.Immutable()
	}
	if obj.Optional {
		builder = builder.Optional()
	}
	if obj.CommentKey != "" {
		if obj.I18nText != nil {
			builder = builder.Comment(obj.I18nText(obj.CommentKey))
		}
	}
	if obj.DefaultFunc != nil {
		builder = builder.DefaultFunc(obj.DefaultFunc)
		obj.UseCustomIDGenerator = false
	}
	if !obj.UseCustomIDGenerator {
		builder = builder.Annotations(entsql.Annotation{
			Incremental: &obj.UseCustomIDGenerator,
		})
	}
	return builder
}

// Fields of the mixin.
func (obj ID) Fields() []ent.Field {
	return []ent.Field{
		obj.PK("id"),
	}
}

func (obj ID) FK(name string) ent.Field {
	obj.Key = name
	obj.Positive = true
	if obj.CommentKey == "" {
		obj.CommentKey = "entity.field.foreign_key.comment"
	}
	return obj.ToField()
}

func (obj ID) PK(name string, fn ...any) ent.Field {
	obj.Key = name
	obj.Unique = true
	obj.Positive = true
	obj.Immutable = true
	obj.UseDefault = true
	if len(fn) > 0 {
		obj.DefaultFunc = fn[0]
	}
	if obj.CommentKey == "" {
		obj.CommentKey = "entity.field.primary_key.comment"
	}
	return obj.ToField()
}

func (obj ID) OP(name string) ent.Field {
	obj.Key = name
	obj.Positive = true
	obj.Optional = true
	if obj.CommentKey == "" {
		obj.CommentKey = "entity.field.optional_key.comment"
	}
	return obj.ToField()
}

func (obj ID) Comment(key string, fns ...func(key string) string) IDGenerator {
	fn := func(key string) string {
		return key
	}
	if len(fns) > 0 {
		fn = fns[0]
	}
	return ID{
		I18nText:   fn,
		CommentKey: key,
	}
}

func (obj ID) UseDefaultFunc(f func() int64) IDGenerator {
	return ID{
		DefaultFunc: f,
	}
}
