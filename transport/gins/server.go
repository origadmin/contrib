/*
 * Copyright (c) 2024 OrigAdmin. All rights reserved.
 */

// Package gins is a gin extension package.
package gins

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"net/url"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/gorilla/mux"

	"github.com/go-kratos/kratos/v2/errors"
	"github.com/go-kratos/kratos/v2/log"
	"github.com/go-kratos/kratos/v2/transport"
)

var (
	_ transport.Server     = (*Server)(nil)
	_ transport.Endpointer = (*Server)(nil)
)

const (
	ErrorTypePrivate = gin.ErrorTypePrivate
)

type (
	Context     = gin.Context
	Engine      = gin.Engine
	HandlerFunc = gin.HandlerFunc
	IRouter     = gin.IRouter
	IRoutes     = gin.IRoutes
	RouterGroup = gin.RouterGroup
	RouteInfo   = gin.RouteInfo
	RoutesInfo  = gin.RoutesInfo
	// WalkRouteFunc is the type of the function called for each route visited by Walk.
	WalkRouteFunc func(RouteInfo) error
)

func New(fns ...gin.OptionFunc) *Engine {
	return gin.New(fns...)
}

type Server struct {
	engine *Engine
	server *http.Server
	lis    net.Listener

	tlsConf *tls.Config
	timeout time.Duration
	network string
	addr    string

	err error

	filters    []HandlerFunc
	middleware HandlerFunc
	//dec        DecodeRequestFunc
	//enc        EncodeResponseFunc
	//ene        EncodeErrorFunc
	endpoint *url.URL
}

func (s *Server) Use(handlers ...HandlerFunc) IRoutes {
	return s.engine.Use(handlers...)
}

func (s *Server) Handle(method, path string, handlers ...HandlerFunc) IRoutes {
	return s.engine.Handle(method, path, handlers...)
}

func (s *Server) Any(path string, handlers ...HandlerFunc) IRoutes {
	return s.engine.Any(path, handlers...)
}

func (s *Server) GET(path string, handlers ...HandlerFunc) IRoutes {
	return s.engine.GET(path, handlers...)
}

func (s *Server) POST(path string, handlers ...HandlerFunc) IRoutes {
	return s.engine.POST(path, handlers...)
}

func (s *Server) DELETE(path string, handlers ...HandlerFunc) IRoutes {
	return s.engine.DELETE(path, handlers...)
}
func (s *Server) PATCH(path string, handlers ...HandlerFunc) IRoutes {
	return s.engine.PATCH(path, handlers...)
}

func (s *Server) PUT(path string, handlers ...HandlerFunc) IRoutes {
	return s.engine.PATCH(path, handlers...)
}

func (s *Server) OPTIONS(path string, handlers ...HandlerFunc) IRoutes {
	return s.engine.OPTIONS(path, handlers...)
}

func (s *Server) HEAD(path string, handlers ...HandlerFunc) IRoutes {
	return s.engine.HEAD(path, handlers...)
}

func (s *Server) Match(methods []string, path string, handlers ...HandlerFunc) IRoutes {
	return s.engine.Match(methods, path, handlers...)
}

func (s *Server) StaticFile(path string, filepath string) IRoutes {
	return s.engine.StaticFile(path, filepath)
}

func (s *Server) StaticFileFS(path string, filepath string, system http.FileSystem) IRoutes {
	return s.engine.StaticFileFS(path, filepath, system)
}

func (s *Server) Static(path string, root string) IRoutes {
	return s.engine.Static(path, root)
}

func (s *Server) StaticFS(path string, system http.FileSystem) IRoutes {
	return s.engine.StaticFS(path, system)
}

func (s *Server) Group(path string, handlers ...HandlerFunc) *RouterGroup {
	return s.engine.Group(path, handlers...)
}

func (s *Server) Route(prefix string, filters ...HandlerFunc) IRoutes {
	var newFilters []HandlerFunc
	newFilters = append(newFilters, s.filters...)
	newFilters = append(newFilters, filters...)
	return s.engine.Group(prefix, newFilters...)
}

// WalkRoute walks the router and all its sub-routers, calling walkFn for each route in the tree.
func (s *Server) WalkRoute(fn WalkRouteFunc) error {
	for _, info := range s.engine.Routes() {
		err := fn(info)
		if err != nil {
			return err
		}
	}
	return nil
}

// WalkHandle walks the router and all its sub-routers, calling walkFn for each route in the tree.
func (s *Server) WalkHandle(handle func(method, path string, handler http.HandlerFunc)) error {
	return s.WalkRoute(func(r RouteInfo) error {
		handle(r.Method, r.Path, s.ServeHTTP)
		return nil
	})
}

func NewServer(opts ...ServerOption) *Server {
	srv := &Server{
		network: "tcp",
		addr:    ":0",
		timeout: 1 * time.Second,
		//dec:     DefaultRequestDecoder,
		//enc:     DefaultResponseEncoder,
		//ene:     DefaultErrorEncoder,
	}

	srv.init(opts...)

	return srv
}

func (s *Server) init(opts ...ServerOption) {
	s.engine = gin.New()

	for _, o := range opts {
		o(s)
	}

	s.server = &http.Server{
		Addr:      s.addr,
		Handler:   s.engine,
		TLSConfig: s.tlsConf,
	}
}

func (s *Server) filter() HandlerFunc {
	return func(c *gin.Context) {
		var (
			ctx    context.Context
			cancel context.CancelFunc
		)
		if s.timeout > 0 {
			ctx, cancel = context.WithTimeout(c.Request.Context(), s.timeout)
		} else {
			ctx, cancel = context.WithCancel(c.Request.Context())
		}
		defer cancel()

		pathTemplate := c.Request.URL.Path
		if route := mux.CurrentRoute(c.Request); route != nil {
			// /path/123 -> /path/{id}
			pathTemplate, _ = route.GetPathTemplate()
		}

		tr := &Transport{
			operation:    pathTemplate,
			pathTemplate: pathTemplate,
			reqHeader:    headerCarrier(c.Request.Header),
			replyHeader:  headerCarrier(c.Writer.Header()),
			ginCtx:       c,
		}
		if s.endpoint != nil {
			tr.endpoint = s.endpoint.String()
		}
		tr.ginCtx.Request = c.Request.WithContext(transport.NewServerContext(ctx, tr))
		tr.ginCtx.Request = c.Request.WithContext(NewContext(c))
		c.Next()
	}
}

func (s *Server) Endpoint() (*url.URL, error) {
	if err := s.listenAndEndpoint(); err != nil {
		return nil, err
	}
	return s.endpoint, nil
}

func (s *Server) Start(ctx context.Context) error {
	if err := s.listenAndEndpoint(); err != nil {
		return err
	}

	log.Infof("[GINS] server listening on: %s", s.lis.Addr().String())
	var err error
	if s.tlsConf != nil {
		err = s.server.ServeTLS(s.lis, "", "")
	} else {
		err = s.server.Serve(s.lis)
	}

	if !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

func (s *Server) Stop(ctx context.Context) error {
	log.Info("[GINS] server stopping")
	return s.server.Shutdown(ctx)
}

func (s *Server) ServeHTTP(res http.ResponseWriter, req *http.Request) {
	s.engine.ServeHTTP(res, req)
}

func (s *Server) listenAndEndpoint() error {
	if s.lis == nil {
		lis, err := net.Listen(s.network, s.addr)
		if err != nil {
			s.err = err
			return err
		}
		s.lis = lis
	}
	if s.endpoint == nil {
		addr, err := extract(s.addr, s.lis)
		if err != nil {
			s.err = err
			return err
		}
		s.endpoint = NewEndpoint(Scheme("http", s.tlsConf != nil), addr)
	}
	s.filters = append(s.filters, s.filter())
	s.engine.Use(s.filters...)
	return s.err
}

var (
	_ transport.Server     = (*Server)(nil)
	_ transport.Endpointer = (*Server)(nil)
	_ http.Handler         = (*Server)(nil)
)
