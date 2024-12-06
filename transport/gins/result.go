/*
 * Copyright (c) 2024 OrigAdmin. All rights reserved.
 */

// Package gins implements the functions, types, and interfaces for the module.
package gins

import (
	"github.com/gin-gonic/gin"
	"github.com/origadmin/toolkits/errors"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
)

var mo = protojson.MarshalOptions{}

// JSON result json data with status code
func JSON(c *gin.Context, status int, data any) {
	if msg, ok := data.(proto.Message); ok {
		buf, err := mo.Marshal(msg)
		if err != nil {
			c.Error(errors.Wrap(err, "marshal proto message error"))
			return
		}
		c.Set(ContextResponseBodBytesKey, buf)
		c.Data(status, "application/json; charset=utf-8", buf)
		c.Abort()
		return
	}
	c.JSON(status, data)
	return
}
