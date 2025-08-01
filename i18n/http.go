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

// tagCtx is an empty struct used as a key for storing Tag information in the context.
type tagCtx struct{}

// WithTags creates a new context with Tag information.
// ctx: The parent context.
// tags: The Tag information to be included in the context.
// Returns a new context containing the Tag information.
func WithTags(ctx context.Context, tags ...Tag) context.Context {
	return context.WithValue(ctx, tagCtx{}, tags)
}

// FromTags retrieves the Tag information from the context.
// ctx: The context from which to retrieve the Tag information.
// Returns a slice of Tag, or a slice containing only the default locale if no Tag information is found.
func FromTags(ctx context.Context) []Tag {
	if tags, ok := ctx.Value(tagCtx{}).([]Tag); ok {
		return tags
	}
	return []Tag{DefaultLocale}
}

// FromTag retrieves the first Tag from the context.
// ctx: The context from which to retrieve the Tag information.
// Returns the first Tag, or the default locale if no Tag information is found or the slice is empty.
func FromTag(ctx context.Context) Tag {
	if tags, ok := ctx.Value(tagCtx{}).([]Tag); ok && len(tags) > 0 {
		return tags[0]
	}
	return DefaultLocale
}

// FromRequest retrieves the Tag information from the HTTP request.
// req: The HTTP request from which to retrieve the Tag information.
// Returns a slice of Tag parsed from the "Accept-Language" header of the request.
func FromRequest(req *http.Request) []language.Tag {
	return ParseAcceptLanguage(req.Header.Get("Accept-Language"))
}

// ParseAcceptLanguage parses the "Accept-Language" header to obtain a slice of language.Tag.
// acceptLanguage: The value of the "Accept-Language" header.
// Returns a slice of language.Tag, or a slice containing only the default locale if parsing fails or the result is empty.
func ParseAcceptLanguage(acceptLanguage string) []language.Tag {
	tags, _, err := language.ParseAcceptLanguage(acceptLanguage)
	if err != nil || len(tags) == 0 {
		return []language.Tag{DefaultLocale}
	}
	return tags
}
