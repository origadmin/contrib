/*
 * Copyright (c) 2024 OrigAdmin. All rights reserved.
 */

// Package tz implements the functions, types, and interfaces for the module.
package tz

import (
	_ "embed"
)

const (
	OffsetZoneName         = 0
	OffsetZoneCountryCode  = 1
	OffsetZoneAbbreviation = 2
	OffsetZoneTimeStart    = 3
	OffsetZoneGmtOffset    = 4
	OffsetZoneDst          = 5
)

// TimeZone zone_name,country_code,abbreviation,time_start,gmt_offset,dst
type TimeZone struct {
	ZoneName     string `json:"zone_name"`
	ZoneID       string `json:"zone_id"`
	CountryCode  string `json:"country_code"`
	Abbreviation string `json:"abbreviation"`
	TimeStart    int64  `json:"time_start"`
	GmtOffset    int64  `json:"gmt_offset"`
	Dst          int64  `json:"dst"` // 1 or 0 means DST
}

//go:embed time_zone.json
var jsonTimeZones []byte
