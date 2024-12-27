/*
 * Copyright (c) 2024 OrigAdmin. All rights reserved.
 */

// Package tz implements the functions, types, and interfaces for the module.
package tz

import (
	_ "embed"
	"encoding/json"
)

const (
	defaultTimeZone = "Asia/Shanghai"
)

var (
	Countries []Country
	TimeZones []TimeZone
)

func init() {
	_ = json.Unmarshal(jsonTimeZones, &TimeZones)
	_ = json.Unmarshal(jsonCountries, &Countries)
}

func Location() string {
	return location()
}

func contains(s []string, e string) bool {
	for _, a := range s {
		if a == e {
			return true
		}
	}
	return false
}
