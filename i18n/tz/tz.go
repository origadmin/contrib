/*
 * Copyright (c) 2024 OrigAdmin. All rights reserved.
 */

// Package tz implements the functions, types, and interfaces for the module.
package tz

import (
	_ "embed"
	"encoding/json"
	"os"
)

const (
	defaultTimeZone = "Asia/Shanghai"
)

//go:embed time_zone.json
var jsonTimeZones []byte

//go:embed country.json
var jsonCountries []byte

func GenerateJSON() error {
	file, err := CountriesFromCSV("country.csv")
	if err != nil {
		return err
	}
	countries, err := json.MarshalIndent(file, "", "  ")
	if err != nil {
		return err
	}
	_ = os.WriteFile("country.json", countries, 0644)
	timeZones, err := TimeZonesFromCSV("time_zone.csv")
	if err != nil {
		return err
	}
	timeZonesJSON, err := json.MarshalIndent(timeZones, "", "  ")
	if err != nil {
		return err
	}
	_ = os.WriteFile("time_zone.json", timeZonesJSON, 0644)
	return nil
}

func Location() string {
	return location()
}
