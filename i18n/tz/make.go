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
	"strconv"
)

func GenerateJSON() error {
	file, err := CountriesFromCSV("data/country.csv")
	if err != nil {
		return err
	}
	countries, err := json.MarshalIndent(file, "", "  ")
	if err != nil {
		return err
	}
	_ = os.WriteFile("country.json", countries, 0644)
	timeZones, err := TimeZonesFromCSV("data/time_zone.csv")
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

func TimeZonesFromCSV(filePath string) ([]TimeZone, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	rd := bufio.NewReader(file)
	reader := csv.NewReader(rd)
	var timeZones []TimeZone
	for {
		line, err := reader.Read()
		if err != nil {
			break
		}
		ts, err := strconv.ParseInt(line[OffsetZoneTimeStart], 10, 64)
		if err != nil {
			return nil, err
		}

		gmto, err := strconv.ParseInt(line[OffsetZoneGmtOffset], 10, 64)
		if err != nil {
			return nil, err
		}
		dst, err := strconv.ParseInt(line[OffsetZoneDst], 10, 64)
		if err != nil {
			return nil, err
		}

		timeZone := TimeZone{
			ZoneName:     line[OffsetZoneName],
			CountryCode:  line[OffsetZoneCountryCode],
			Abbreviation: line[OffsetZoneAbbreviation],
			TimeStart:    ts,
			GmtOffset:    gmto,
			Dst:          dst,
			//ZoneNameOffset: int32(zno),
		}
		timeZones = append(timeZones, timeZone)
	}
	return timeZones, nil
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
