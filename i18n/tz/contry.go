/*
 * Copyright (c) 2024 OrigAdmin. All rights reserved.
 */

// Package tz implements the functions, types, and interfaces for the module.
package tz

import (
	"bufio"
	"encoding/csv"
	"encoding/json"
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

var (
	Countries []Country
)

func init() {
	err := json.Unmarshal(jsonCountries, &Countries)
	if err != nil {
		return
	}
}

func CountriesFromCSV(filePath string) ([]Country, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	rd := bufio.NewReader(file)
	reader := csv.NewReader(rd)
	var countries []Country
	for {
		line, err := reader.Read()
		if err != nil {
			break
		}
		country := Country{
			CountryName: line[OffsetCountryName],
			CountryCode: line[OffsetCountryCode],
		}
		countries = append(countries, country)
	}
	return countries, nil
}
