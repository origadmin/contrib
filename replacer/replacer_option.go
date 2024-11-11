// Copyright (c) 2024 OrigAdmin. All rights reserved.

// Package replacer provides a string Replacement mechanism with custom Replacement functions and keywords.
package replacer

// Setting is the setting of replacer.
type Setting = func(*Replacement)

// WithHook returns a new Replacer instance with the specified hooks.
func WithHook(hook ReplaceFunc) Setting {
	return func(o *Replacement) {
		o.hook = hook
	}
}

// WithStart returns a new Replacer instance with replacer start keyword.
func WithStart(keyword string) Setting {
	return func(o *Replacement) {
		o.sta = keyword
	}
}

// WithEnd returns a new Replacer instance with replacer end keyword.
func WithEnd(keyword string) Setting {
	return func(o *Replacement) {
		o.end = keyword
	}
}

// WithKeyword returns a new Replacer instance with the specified keyword.
func WithKeyword(keyword string) Setting {
	return func(o *Replacement) {
		o.sta = keyword
		o.end = keyword
	}
}

// WithFold returns a new Replacer instance with string case folding.
func WithFold(fold bool) Setting {
	return func(o *Replacement) {
		o.fold = fold
	}
}

// WithSeparator returns a new Replacer instance with the specified separator.
func WithSeparator(sep string) Setting {
	return func(o *Replacement) {
		o.sep = sep
	}
}
