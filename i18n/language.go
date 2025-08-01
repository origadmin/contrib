/*
 * Copyright (c) 2024 OrigAdmin. All rights reserved.
 */

// Package i18n implements the functions, types, and interfaces for the module.
package i18n

// LanguageStrings returns a list of language strings for all languages in the Languages slice.
func LanguageStrings() []string {
	// Initialize an empty slice to store the language strings
	var languages []string
	// Iterate over each language in the Languages slice
	for _, lang := range Languages {
		// Append the language string to the slice
		languages = append(languages, languageBaseScript(lang))
	}
	// Return the slice of language strings
	return languages
}

// String2Language converts a locale string to a language tag.
func String2Language(localeString string) Tag {
	// Convert the locale string to a language tag
	lang := Make(localeString)
	// Apply the languageBaseScript function to the language tag
	return Make(languageBaseScript(lang))
}

// Unknown2Language converts an unknown language tag to a language tag.
func Unknown2Language(lang Tag) Tag {
	// Apply the languageBaseScript function to the input tag
	return Make(languageBaseScript(lang))
}
