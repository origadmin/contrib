/*
 * Copyright (c) 2024 OrigAdmin. All rights reserved.
 */

// Package gins is a gin extension package.
package gins

import (
	"errors"
	"net"
	"net/http"
	"net/http/httputil"
	"os"
	"runtime/debug"
	"strings"
	"time"

	"github.com/go-kratos/kratos/v2/log"
	"github.com/go-kratos/kratos/v2/middleware"
	"github.com/origadmin/runtime/context"
	"github.com/origadmin/toolkits/errors/httperr"
)

// Logger receives the gin framework default log
func Logger(logger log.Logger) HandlerFunc {
	return func(c *Context) {
		start := time.Now()
		path := c.Request.URL.Path
		query := c.Request.URL.RawQuery
		c.Next()
		//"status":     c.Writer.Status(),
		//	"method":     c.Request.Method,
		//	"path":       path,
		//	"ip":         c.ClientIP(),
		//	"latency":    latency,
		//	"user-agent": c.Request.UserAgent(),
		//	"time":       end.Format(timeFormat),
		cost := time.Since(start)
		_ = logger.Log(log.LevelInfo,
			"status", c.Writer.Status(),
			"method", c.Request.Method,
			"path", path,
			"query", query,
			"ip", c.ClientIP(),
			"user-agent", c.Request.UserAgent(),
			"errors", c.Errors.ByType(ErrorTypePrivate).String(),
			"cost", cost,
		)
	}
}

// Recovery recover any panic that may occur in the project
func Recovery(logger log.Logger, stack bool) HandlerFunc {
	return func(c *Context) {
		defer func() {
			if err, ok := recover().(error); ok {
				// Check for a broken connection, as it is not really a
				// condition that warrants a panic stack trace.
				var brokenPipe bool
				var ne *net.OpError
				if errors.As(err, &ne) {
					var se *os.SyscallError
					if errors.As(ne.Err, &se) {
						if strings.Contains(strings.ToLower(se.Error()), "broken pipe") || strings.Contains(strings.ToLower(se.Error()), "connection reset by peer") {
							brokenPipe = true
						}
					}
				}

				httpRequest, _ := httputil.DumpRequest(c.Request, false)
				if brokenPipe {
					_ = logger.Log(log.LevelError,
						"path", c.Request.URL.Path,
						"error", err,
						"request", string(httpRequest),
					)
					// If the connection is dead, we can't write a status to it.
					_ = c.Error(err.(error))
					c.Abort()
					return
				}

				if stack {
					_ = logger.Log(log.LevelError,
						"[Recovery from panic]",
						"error", err,
						"request", string(httpRequest),
						"stack", string(debug.Stack()),
					)
				} else {
					_ = logger.Log(log.LevelError,
						"[Recovery from panic]",
						"error", err,
						"request", string(httpRequest),
					)
				}
				c.AbortWithStatus(http.StatusInternalServerError)
			}
		}()
		c.Next()
	}
}

// Middlewares return middlewares wrapper
func Middlewares(m ...middleware.Middleware) HandlerFunc {
	chain := middleware.Chain(m...)
	return func(c *Context) {
		next := func(ctx context.Context, req interface{}) (interface{}, error) {
			c.Next()
			var err error
			if c.Writer.Status() >= http.StatusBadRequest {
				err = httperr.New("", int32(c.Writer.Status()), "unknown")
			}
			return c.Writer, err
		}
		next = chain(next)
		ctx := NewContext(c)
		c.Request = c.Request.WithContext(ctx)
		SetOperation(ctx, c.FullPath())
		_, _ = next(c.Request.Context(), c.Request)
	}
}
