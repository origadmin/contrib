/*
 * Copyright (c) 2024 OrigAdmin. All rights reserved.
 */

// Package gins is a gin extension package.
package gins

import (
	"io"
	"net/http"

	"github.com/gin-gonic/gin/binding"
)

const (
	ContextRequestBodyBytesKey = "_gins_context_request_body_bytes"
	ContextResponseBodBytesKey = "_gins_context_response_body_bytes"
)

type jsonBinding struct{}

var bind = new(jsonBinding)

func (u jsonBinding) Name() string {
	return "json"
}

func (u jsonBinding) BindUri(m map[string][]string, obj any) error {
	return binding.MapFormWithTag(obj, m, u.Name())
}

func (u jsonBinding) BindQuery(req *http.Request, obj any) error {
	values := req.URL.Query()
	if err := binding.MapFormWithTag(obj, values, u.Name()); err != nil {
		return err
	}
	return validate(obj)
}

func (u jsonBinding) Bind(req *http.Request, obj any) error {
	return binding.JSON.Bind(req, obj)
}

func (u jsonBinding) BindBody(body []byte, obj any) error {
	return binding.JSON.BindBody(body, obj)
}

// Bind is bind json body to target.
func Bind(ctx *Context, obj any) error {
	return bind.Bind(ctx.Request, obj)
}

// BindURI bind form parameters to target.
func BindURI(ctx *Context, target interface{}) error {
	m := make(map[string][]string, len(ctx.Params))
	for _, v := range ctx.Params {
		m[v.Key] = []string{v.Value}
	}
	return bind.BindUri(m, target)
}

// BindQuery bind query parameters to target.
func BindQuery(ctx *Context, target interface{}) error {
	return bind.BindQuery(ctx.Request, target)
}

// BindBody bind json body to target.
func BindBody(ctx *Context, obj any) error {
	var body []byte
	var err error
	if cb, ok := ctx.Get(ContextRequestBodyBytesKey); ok {
		if cbb, ok := cb.([]byte); ok {
			body = cbb
		}
	}
	if body == nil {
		body, err = io.ReadAll(ctx.Request.Body)
		if err != nil {
			return err
		}
		ctx.Set(ContextRequestBodyBytesKey, body)
	}
	return bind.BindBody(body, obj)
}

func validate(obj any) error {
	if binding.Validator == nil {
		return nil
	}
	return binding.Validator.ValidateStruct(obj)
}
