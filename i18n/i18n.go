/*
 * Copyright (c) 2024 OrigAdmin. All rights reserved.
 */

// Package i18n implements the functions, types, and interfaces for the module.
package i18n

import (
	"fmt"

	"github.com/godcong/go-locale/v2"
	"golang.org/x/text/language"
)

const (
	defaultLocale = "en_US"
)

var (
	// Locales is the current system language settings
	Locales   = locale.Languages()
	Languages = []language.Tag{
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
func PreferredLocale(supportedLocales ...string) string {
	for _, localeTag := range Locales {
		for _, supportedLocale := range supportedLocales {
			if localeTag.String() == supportedLocale {
				return supportedLocale
			}
		}
	}
	return defaultLocale
}

func Compare(lt, rt language.Tag) int {
	baseLT, _ := lt.Base()
	baseRT, _ := rt.Base()
	if baseLT.String() != baseRT.String() {
		return 0
	}
	scriptLT, _ := lt.Script()
	scriptRT, _ := rt.Script()
	if scriptLT.String() != scriptRT.String() {
		return 0
	}
	regionLT, _ := lt.Region()
	regionRT, _ := rt.Region()
	if regionLT.String() != regionRT.String() {
		return 0
	}
	return 1
}

func LanguageStrings() []string {
	var langs []string
	for _, lang := range Languages {
		langs = append(langs, lang.String())
	}
	return langs
}

func CountryStrings() []string {
	var langs []string
	for _, lang := range Languages {
		b, _ := lang.Base()
		r, _ := lang.Region()
		langs = append(langs, fmt.Sprintf("%s-%s", b, r))
	}
	return langs
}

func String2Language(lang string) language.Tag {
	tag := language.Make(lang)
	b, _ := tag.Base()
	s, _ := tag.Script()
	return language.Make(fmt.Sprintf("%s-%s", b, s))
}

func Language2Language(lang language.Tag) language.Tag {
	b, _ := lang.Base()
	s, _ := lang.Script()
	return language.Make(fmt.Sprintf("%s-%s", b, s))
}

func Language2Country(lang language.Tag) language.Tag {
	b, _ := lang.Base()
	r, _ := lang.Region()
	return language.Make(fmt.Sprintf("%s-%s", b, r))
}

func CountryLanguage(lang language.Tag) language.Tag {
	b, _ := lang.Base()
	s, _ := lang.Script()
	r, _ := lang.Region()
	return language.Make(fmt.Sprintf("%s-%s-%s", b, s, r))
}
