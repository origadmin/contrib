/*
 * Copyright (c) 2024 OrigAdmin. All rights reserved.
 */

// Package tz implements the functions, types, and interfaces for the module.
package tz

import (
	"bufio"
	_ "embed"
	"encoding/csv"
	"os"
)

const (
	OffsetCountryName = 0
	OffsetCountryCode = 1
)

// Country country_name,country_code
type Country struct {
	CountryName string `json:"country_name"`
	CountryCode string `json:"country_code"`
}

//go:embed country.json
var jsonCountries []byte
