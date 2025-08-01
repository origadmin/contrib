/*
 * Copyright (c) 2024 OrigAdmin. All rights reserved.
 */

// Package mixin implements the functions, types, and interfaces for the module.
package mixin

import (
	"entgo.io/ent"
)

type BaseID[T any] struct {
	Key         string
	CommentKey  string
	Optional    bool
	UseDefault  bool
	DefaultFunc any
	Unique      bool
	Immutable   bool
	GenFunc     func() ent.Field
}

var (
	ModelMixin = []ent.Mixin{
		ID{},
		CreateSchema{},
		UpdateSchema{},
	}
	AuditModelMixin = []ent.Mixin{
		ID{},
		Audit[int64]{},
		CreateSchema{},
		UpdateSchema{},
	}
)
