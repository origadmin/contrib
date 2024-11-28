/*
 * Copyright (c) 2024 OrigAdmin. All rights reserved.
 */

// Package gins implements the functions, types, and interfaces for the module.
package gins

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/goexts/generic/maps"
	"github.com/origadmin/runtime/context"
	"github.com/origadmin/toolkits/errors"
	"github.com/origadmin/toolkits/errors/httperr"
	"github.com/origadmin/toolkits/net/pagination"
)

type Result struct {
	pagination.UnimplementedResponder `json:"-"`
	Success                           bool           `json:"success"`
	Total                             int64          `json:"total,omitempty"`
	Data                              any            `json:"data,omitempty"`
	Extra                             any            `json:"extra,omitempty"`
	Error                             *httperr.Error `json:"error,omitempty"`
}

func (r Result) GetData() any {
	return r.Data
}

func (r Result) GetSuccess() bool {
	return r.Success
}

// ResultJSON result json data with status code
func ResultJSON(c *gin.Context, status int, resp pagination.Responder) {
	buf, err := json.Marshal(resp.GetData())
	if err != nil {
		panic(err)
	}

	c.Set(ContextResponseBodBytesKey, buf)
	c.Data(status, "application/json; charset=utf-8", buf)
	c.Abort()
}

// ResultSuccess result success data with status code
func ResultSuccess(c *gin.Context, resp pagination.Responder) {
	ResultJSON(c, http.StatusOK, Result{
		Success: true,
		Data:    resp.GetData(),
	})
}

// ResultOK result success data with status code
func ResultOK(c *gin.Context) {
	ResultJSON(c, http.StatusOK, Result{
		Success: true,
	})
}

// ResultPage result page data with status code
func ResultPage(c *gin.Context, resp pagination.Responder, args ...map[string]any) {
	extra := resp.GetExtra()
	if extra == nil && len(args) > 0 {
		maps.MergeMaps(args[0], args[1:]...)
		extra = args[0]
	}
	ResultJSON(c, http.StatusOK, Result{
		Success: true,
		Data:    resp.GetData(),
		Extra:   extra,
		Total:   int64(resp.GetTotal()),
	})
}

// ResultError result error data with status code
func ResultError(c *Context, err error, status ...int) {
	var ierr *httperr.Error
	if ok := errors.As(err, &ierr); !ok {
		ierr = httperr.FromError(httperr.InternalServerError(err.Error())) // default error
	}

	code := int(ierr.Code)
	if len(status) > 0 {
		code = status[0]
	}

	if code >= 500 {
		ctx := c.Request.Context()
		//ctx = context.NewTag(ctx, logging.TagKeySystem)
		ctx = context.NewStack(ctx, fmt.Sprintf("%+v", err))
		//logging.Context(ctx).LogAttrs(ctx, slog.LevelError, "Internal server error", slog.Any("error", err))
		ierr.Detail = http.StatusText(http.StatusInternalServerError)
	}

	ierr.Code = int32(code)
	_ = c.Error(gin.Error{
		Err:  ierr,
		Type: gin.ErrorTypeAny,
		Meta: c.Request.URL.RawQuery,
	})
	ResultJSON(c, code, Result{
		Error: ierr,
	})
}
