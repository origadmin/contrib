/*
 * Copyright (c) 2024 OrigAdmin. All rights reserved.
 */

// Package i18n implements the functions, types, and interfaces for the module.
package i18n

import (
	"golang.org/x/text/language"
)

type (
	Tag = language.Tag
)

func Make(lang string) language.Tag {
	return language.Make(lang)
}

func Parse(tag string) (language.Tag, error) {
	return language.Parse(tag)
}
