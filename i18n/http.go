/*
 * Copyright (c) 2024 OrigAdmin. All rights reserved.
 */

// Package i18n implements the functions, types, and interfaces for the module.
package i18n

import (
	"context"
	"net/http"

	"golang.org/x/text/language"
)

type languageCtx struct{}

func WithContext(ctx context.Context, tag Tag) context.Context {
	return context.WithValue(ctx, languageCtx{}, tag)
}
func FromContext(ctx context.Context) Tag {
	if tag, ok := ctx.Value(languageCtx{}).(Tag); ok {
		return tag
	}
	return DefaultLocale
}
func LanguageFromRequest(req *http.Request) *http.Request {
	tags, _, err := language.ParseAcceptLanguage(req.Header.Get("Accept-Language"))
	tag := DefaultLocale
	if err == nil && len(tags) > 0 {
		tag = tags[0]
	}

	return req.WithContext(WithContext(req.Context(), tag))
}
