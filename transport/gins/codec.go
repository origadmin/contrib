/*
 * Copyright (c) 2024 OrigAdmin. All rights reserved.
 */

// Package gins is a gin extension package.
package gins

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/go-kratos/kratos/v2/encoding"
	"github.com/go-kratos/kratos/v2/errors"
	"github.com/go-kratos/kratos/v2/transport/http/binding"
	"github.com/gorilla/mux"
)

// Redirector replies to the request with a redirect to url
// which may be a path relative to the request path.
type Redirector interface {
	Redirect() (string, int)
}

// Request type net/http.
type Request = http.Request

// ResponseWriter type net/http.
type ResponseWriter = http.ResponseWriter

// Flusher type net/http
type Flusher = http.Flusher

// DecodeRequestFunc is decode request func.
type DecodeRequestFunc func(*Context, interface{}) error

// EncodeResponseFunc is encode response func.
type EncodeResponseFunc func(*Context, interface{}) error

// EncodeErrorFunc is encode error func.
type EncodeErrorFunc func(*Context, error)

// DefaultRequestVars decodes the request vars to object.
func DefaultRequestVars(c *Context, v interface{}) error {
	raws := mux.Vars(c.Request)
	vars := make(url.Values, len(raws))
	for k, v := range raws {
		vars[k] = []string{v}
	}
	return binding.BindQuery(vars, v)
}

// DefaultRequestQuery decodes the request vars to object.
func DefaultRequestQuery(c *Context, v interface{}) error {
	return binding.BindQuery(c.Request.URL.Query(), v)
}

// DefaultRequestDecoder decodes the request body to object.
func DefaultRequestDecoder(c *Context, v interface{}) error {
	r := c.Request
	codec, ok := CodecForRequest(c, "Content-Type")
	if !ok {
		return errors.BadRequest("CODEC", fmt.Sprintf("unregister Content-Type: %s", r.Header.Get("Content-Type")))
	}
	data, err := io.ReadAll(r.Body)

	// reset body.
	r.Body = io.NopCloser(bytes.NewBuffer(data))

	if err != nil {
		return errors.BadRequest("CODEC", err.Error())
	}
	if len(data) == 0 {
		return nil
	}
	if err = codec.Unmarshal(data, v); err != nil {
		return errors.BadRequest("CODEC", fmt.Sprintf("body unmarshal %s", err.Error()))
	}
	return nil
}

// DefaultResponseEncoder encodes the object to the HTTP response.
func DefaultResponseEncoder(c *Context, v interface{}) error {
	if v == nil {
		return nil
	}
	//c.Redirect
	if rd, ok := v.(Redirector); ok {
		url, code := rd.Redirect()
		c.Redirect(code, url)
		return nil
	}
	codec, _ := CodecForRequest(c, "Accept")
	data, err := codec.Marshal(v)
	if err != nil {
		return err
	}
	w := c.Writer
	w.Header().Set("Content-Type", ContentType(codec.Name()))
	_, err = w.Write(data)
	if err != nil {
		return err
	}
	return nil
}

// DefaultErrorEncoder encodes the error to the HTTP response.
func DefaultErrorEncoder(c *Context, err error) {
	se := errors.FromError(err)
	codec, _ := CodecForRequest(c, "Accept")
	body, err := codec.Marshal(se)
	if err != nil {
		c.Status(http.StatusInternalServerError)
		return
	}
	w := c.Writer
	w.Header().Set("Content-Type", ContentType(codec.Name()))
	w.WriteHeader(int(se.Code))
	_, _ = w.Write(body)
}

// CodecForRequest get encoding.Codec via http.Request
func CodecForRequest(c *Context, name string) (encoding.Codec, bool) {
	r := c.Request
	for _, accept := range r.Header[name] {
		codec := encoding.GetCodec(CodecName(accept))
		if codec != nil {
			return codec, true
		}
	}
	return encoding.GetCodec("json"), false
}

const (
	baseContentType = "application"
)

// ContentType returns the content-type with base prefix.
func ContentType(subtype string) string {
	return baseContentType + "/" + subtype
}

// CodecName returns the content-type with base prefix.
func CodecName(name string) string {
	return strings.TrimPrefix(name, baseContentType+"/")
}
