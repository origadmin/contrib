/*
 * Copyright (c) 2024 OrigAdmin. All rights reserved.
 */

// Package i18n implements the functions, types, and interfaces for the module.
package i18n

import (
	"fmt"
)

func ignoreR[L any, R any](l L, r R) L {
	return l
}

func ignoreL[L any, R any](l L, r R) R {
	return r
}

func baseRegion(base string, region string) string {
	return fmt.Sprintf("%s-%s", base, region)
}

func baseScript(base string, script string) string {
	return fmt.Sprintf("%s-%s", base, script)
}

func baseScriptRegion(base string, script string, region string) string {
	if script == "" {
		return baseScript(base, region)
	}
	if region == "" {
		return baseRegion(base, script)
	}
	return fmt.Sprintf("%s-%s-%s", base, script, region)
}

func languageBase(lang Tag) string {
	return ignoreR(lang.Base()).String()
}

func languageScript(lang Tag) string {
	return ignoreR(lang.Script()).String()
}

func languageRegion(lang Tag) string {
	return ignoreR(lang.Region()).String()
}

func languageBaseScript(lang Tag) string {
	return baseScript(languageBase(lang), languageScript(lang))
}

func languageBaseRegion(lang Tag) string {
	return baseRegion(languageBase(lang), languageRegion(lang))
}
func languageBaseScriptRegion(lang Tag) string {
	return baseScriptRegion(languageBase(lang), languageScript(lang), languageRegion(lang))
}
