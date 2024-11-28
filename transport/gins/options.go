/*
 * Copyright (c) 2024 OrigAdmin. All rights reserved.
 */

// Package gins is a gin extension package.
package gins

import (
	"crypto/tls"
	"net"
	"net/url"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/go-kratos/kratos/v2/log"
	"github.com/go-kratos/kratos/v2/middleware"
)

type ServerOption func(*Server)

func WithTLSConfig(c *tls.Config) ServerOption {
	return func(s *Server) {
		s.tlsConf = c
	}
}

func Address(addr string) ServerOption {
	return func(s *Server) {
		s.addr = addr
	}
}

//func ErrorEncoder(en EncodeErrorFunc) ServerOption {
//	return func(s *Server) {
//		s.ene = en
//	}
//}

func StrictSlash(strictSlash bool) ServerOption {
	return func(s *Server) {
		if s.engine == nil {
			s.engine = New()
		}
		s.engine.RedirectTrailingSlash = strictSlash
	}
}

// WithLogger inject info logger
func WithLogger(l log.Logger) ServerOption {
	return func(s *Server) {
		gin.DefaultWriter = &infoLogger{Logger: l}
		gin.DefaultErrorWriter = &errLogger{Logger: l}
		s.engine.Use(Logger(l), Recovery(l, true))
	}
}

// Network with server network.
func Network(network string) ServerOption {
	return func(s *Server) {
		s.network = network
	}
}

// Endpoint with server address.
func Endpoint(endpoint *url.URL) ServerOption {
	return func(s *Server) {
		s.endpoint = endpoint
	}
}

// Timeout with server timeout.
func Timeout(timeout time.Duration) ServerOption {
	return func(s *Server) {
		s.timeout = timeout
	}
}

// Middleware with service middleware option.
func Middleware(m ...middleware.Middleware) ServerOption {
	return func(o *Server) {
		o.middleware = Middlewares(m...)
	}
}

// Filter with HTTP middleware option.
func Filter(filters ...HandlerFunc) ServerOption {
	return func(o *Server) {
		o.filters = filters
	}
}

// RequestDecoder with request decoder.
//func RequestDecoder(dec DecodeRequestFunc) ServerOption {
//	return func(o *Server) {
//		o.dec = dec
//	}
//}

// ResponseEncoder with response encoder.
//func ResponseEncoder(en EncodeResponseFunc) ServerOption {
//	return func(o *Server) {
//		o.enc = en
//	}
//}

// TLSConfig with TLS config.
func TLSConfig(c *tls.Config) ServerOption {
	return func(o *Server) {
		o.tlsConf = c
	}
}

// Listener with server lis
func Listener(lis net.Listener) ServerOption {
	return func(s *Server) {
		s.lis = lis
	}
}

func NotFoundHandler(handlers ...HandlerFunc) ServerOption {
	return func(s *Server) {
		s.engine.NoRoute(handlers...)
	}
}

func MethodNotAllowedHandler(handlers ...HandlerFunc) ServerOption {
	return func(s *Server) {
		s.engine.NoMethod(handlers...)
	}
}
