/*
 * Copyright (c) 2024 OrigAdmin. All rights reserved.
 */

// Package i18n implements the functions, types, and interfaces for the module.
package i18n

// CountryStrings returns a list of country strings based on the supported languages.
func CountryStrings() []string {
	// Initialize an empty slice to store the country strings.
	var countries []string
	// Iterate over the supported languages.
	for _, lang := range Languages {
		// Convert each language to its corresponding country string using the languageBaseRegion function.
		countries = append(countries, languageBaseRegion(lang))
	}
	// Return the list of country strings.
	return countries
}

// String2Country converts a locale string to a country tag.
func String2Country(localeString string) Tag {
	// Convert the locale string to a language tag using the Make function.
	lang := Make(localeString)
	// Convert the language tag to a country tag using the languageBaseRegion function and Make function.
	return Make(languageBaseRegion(lang))
}

// Unknown2Country converts an unknown language tag to a country tag.
func Unknown2Country(lang Tag) Tag {
	// Convert the unknown language tag to a country tag using the languageBaseRegion function and Make function.
	return Make(languageBaseRegion(lang))
}
