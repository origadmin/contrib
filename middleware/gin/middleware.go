/*
 * Copyright (c) 2024 OrigAdmin. All rights reserved.
 */

package gin

import (
	"fmt"

	"github.com/origadmin/runtime/context"
)

type reporter struct {
	ctx       context.Context
	code      int
	method    string
	handler   string
	succeed   bool
	latency   float64
	readSize  int64
	writeSize int64
}

func (g reporter) Code() string {
	return fmt.Sprintf("%d", g.code)
}

func (g reporter) Latency() int64 {
	return int64(g.latency)
}

func (g reporter) Handler() string {
	return g.handler
}

func (g reporter) Method() string {
	return g.method
}

func (g reporter) Context() context.Context {
	return g.ctx
}

// WriteSize returns the number of bytes sent in the response
func (g reporter) WriteSize() int64 {
	return g.writeSize
}

// ReadSize returns the number of bytes received in the request
func (g reporter) ReadSize() int64 {
	return g.readSize
}

// Succeed returns whether the request was successful or not
func (g reporter) Succeed() bool {
	return g.succeed
}

// TraceID returns the trace ID of the request
func (g reporter) TraceID() string {
	return context.FromTrace(g.ctx)
}
