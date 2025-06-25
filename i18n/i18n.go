/*
 * Copyright (c) 2024 OrigAdmin. All rights reserved.
 */

// Package i18n implements the functions, types, and interfaces for the module.
package i18n

import (
	"github.com/godcong/go-locale/v2"
	"golang.org/x/text/language"
)

const (
	defaultLocaleString = "en_US"
)

var (
	// Locales is the current system language settings
	Locales = locale.Languages()
	// DefaultLocale is the default system language settings
	DefaultLocale = Make(defaultLocaleString)
	Languages     = []Tag{
		language.Afrikaans,
		language.Amharic,
		language.Arabic,
		language.ModernStandardArabic,
		language.Azerbaijani,
		language.Bulgarian,
		language.Bengali,
		language.Catalan,
		language.Czech,
		language.Danish,
		language.German,
		language.Greek,
		language.English,
		language.AmericanEnglish,
		language.BritishEnglish,
		language.Spanish,
		language.EuropeanSpanish,
		language.LatinAmericanSpanish,
		language.Estonian,
		language.Persian,
		language.Finnish,
		language.Filipino,
		language.French,
		language.CanadianFrench,
		language.Gujarati,
		language.Hebrew,
		language.Hindi,
		language.Croatian,
		language.Hungarian,
		language.Armenian,
		language.Indonesian,
		language.Icelandic,
		language.Italian,
		language.Japanese,
		language.Georgian,
		language.Kazakh,
		language.Khmer,
		language.Kannada,
		language.Korean,
		language.Kirghiz,
		language.Lao,
		language.Lithuanian,
		language.Latvian,
		language.Macedonian,
		language.Malayalam,
		language.Mongolian,
		language.Marathi,
		language.Malay,
		language.Burmese,
		language.Nepali,
		language.Dutch,
		language.Norwegian,
		language.Punjabi,
		language.Polish,
		language.Portuguese,
		language.BrazilianPortuguese,
		language.EuropeanPortuguese,
		language.Romanian,
		language.Russian,
		language.Sinhala,
		language.Slovak,
		language.Slovenian,
		language.Albanian,
		language.Serbian,
		language.SerbianLatin,
		language.Swedish,
		language.Swahili,
		language.Tamil,
		language.Telugu,
		language.Thai,
		language.Turkish,
		language.Ukrainian,
		language.Urdu,
		language.Uzbek,
		language.Vietnamese,
		language.Chinese,
		language.SimplifiedChinese,
		language.TraditionalChinese,
		language.Zulu,
	}
)

// PreferredLocale gets the current system language settings
// multi-language are supported, the first match is returned
// if no match is found, the default system language settings is returned
func PreferredLocale(acceptLanguage string) string {
	localeStrings, _, err := language.ParseAcceptLanguage(acceptLanguage)
	if err != nil {
		return defaultLocaleString
	}
	m := language.NewMatcher(Locales)
	tag, index, c := m.Match(localeStrings...)
	if c == 0 {
		return tag.String()
	}
	if index < len(Locales) {
		return Locales[index].String()
	}
	return defaultLocaleString
}

// Compare compares two language tags and returns 1 if they match, 0 otherwise.
func Compare(lt, rt Tag) int {
	// Check if the language bases match
	if languageBase(lt) != languageBase(rt) {
		return 0
	}
	// Check if the language scripts match
	if languageScript(lt) != languageScript(rt) {
		return 0
	}
	// Check if the language regions match
	if languageRegion(lt) != languageRegion(rt) {
		return 0
	}
	// If all components match, return 1
	return 1
}

// Language2Country converts a language tag to a country tag.
func Language2Country(lang Tag) Tag {
	// Create a new tag with the language base and region
	return Make(languageBaseRegion(lang))
}

// Country2Language converts a country tag to a language tag.
func Country2Language(lang Tag) Tag {
	// Create a new tag with the language base and script
	return Make(languageBaseScript(lang))
}

// CountryLanguage converts a country tag to a language tag with region.
func CountryLanguage(lang Tag) Tag {
	// Create a new tag with the language base, script, and region
	return Make(languageBaseScriptRegion(lang))
}
