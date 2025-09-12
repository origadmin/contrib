/*
 * Copyright (c) 2024 OrigAdmin. All rights reserved.
 */

// Package replacer provides a string Replacement mechanism with custom Replacement functions and keywords.
package replacer

import (
	"strings"

	"github.com/goexts/generic/configure"
)

const (
	defaultStartKeyword     = "${"
	defaultEndKeyword       = "}"
	defaultSeparatorKeyword = ":"

	defaultHostStartKeyword     = "@{"
	defaultHostEndKeyword       = "}"
	defaultHostSeparatorKeyword = "="

	defaultMatchStartKeyword     = "@"
	defaultMatchEndKeyword       = ":"
	defaultMatchSeparatorKeyword = "="
)

// ReplaceFunc is a function type that accepts a string and returns a replaced string.
type ReplaceFunc func(src, key, value string, fold bool) (string, bool)

// Replacer interface defines methods for setting keywords and performing replacements.
type Replacer interface {
	Replace(content []byte, replacements map[string]string) []byte // Replaces substrings based on provided key-value pairs.
	ReplaceString(content string, replacements map[string]string) string
}

// Replace replaces substrings within the provided content byte slice using the provided key-value pairs.
func Replace(content []byte, replacements map[string]string) []byte {
	return _globalReplacer.Replace(content, replacements)
}

// ReplaceString replaces substrings within the provided content string using the provided key-value pairs.
func ReplaceString(content string, replacements map[string]string) string {
	return _globalReplacer.ReplaceString(content, replacements)
}

// Replacement struct implements the Replacer interface, storing Replacement hooks and the current keyword.
type Replacement struct {
	offset int
	sta    string
	end    string
	sep    string
	hook   ReplaceFunc
	fold   bool
}

func (r Replacement) ToMatch(replacements map[string]string) Matcher {
	return NewMatch(
		replacements,
		WithMatchSta(r.sta),
		WithMatchEnd(r.end),
		WithMatchFold(r.fold),
		WithMatchSeparator(r.sep))
}

// ReplaceString replaces substrings within the provided content string using the provided key-value pairs.
func (r Replacement) ReplaceString(content string, replacements map[string]string) string {
	return string(r.Replace([]byte(content), replacements))
}

// Replace within the Replacement struct iterates through the values map, applying custom hooks and
// replacing placeholders found in the source string.
func (r Replacement) Replace(content []byte, replacements map[string]string) []byte {
	m := r.ToMatch(replacements)
	return m.ReplaceBytes(content)
}

func defaultReplacer(src, key, value string, fold bool) (string, bool) {
	switch {
	case fold && value != "" && strings.EqualFold(key, src):
		return value, true
	case value != "" && key == src:
		return value, true
	default:
		return "", false
	}
}

// New returns a new Replacer instance with default settings.
func New(ss ...Setting) *Replacement {
	r := settings.Apply(&Replacement{
		sta:  defaultStartKeyword,
		end:  defaultEndKeyword,
		sep:  defaultSeparatorKeyword,
		hook: defaultReplacer,
	}, ss)

	r.offset = len(r.sta)
	return r
}

// NewHost returns a new Replacer instance with default host settings.
func NewHost(ss ...Setting) *Replacement {
	r := settings.Apply(&Replacement{
		fold: true,
		sta:  defaultHostStartKeyword,
		end:  defaultHostEndKeyword,
		sep:  defaultHostSeparatorKeyword,
		hook: defaultReplacer,
	}, ss)

	r.offset = len(r.sta)
	return r
}

var (
	_globalReplacer = NewHost()
)
