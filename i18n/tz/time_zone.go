/*
 * Copyright (c) 2024 OrigAdmin. All rights reserved.
 */

// Package tz implements the functions, types, and interfaces for the module.
package tz

import (
	"bufio"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"time"
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
	//ZoneNameOffset int32  `json:"zone_name_offset"`
}

var (
	TimeZones []TimeZone
)

func init() {
	err := json.Unmarshal(jsonTimeZones, &TimeZones)
	if err != nil {
		return
	}
}

func TimeZoneFrom(abbr string, gmt int64, dst int64) (TimeZone, error) {
	name, offset := time.Now().Local().Zone()
	fmt.Println(name, offset)
	t := time.Unix(-2177481943, 0)
	fmt.Println("SH", t, time.Now().Local().IsDST())
	sta, end := time.Now().Local().ZoneBounds()
	fmt.Println(sta.Unix(), end)
	for idx, tz := range TimeZones {
		if tz.Abbreviation != abbr {
			continue
		}
		if tz.GmtOffset != gmt {
			continue
		}
		fmt.Println(idx, tz.ZoneName)
		//fmt.Println(tz.GmtOffset, gmt)
		fmt.Println(tz.Dst, dst)
		if tz.Dst != dst {
			continue
		}

		return tz, nil

	}
	return TimeZone{}, nil
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
		//zno, err := strconv.ParseInt(line[OffsetZoneNameOffset], 10, 32)
		//if err != nil {
		//	return nil, err
		//}

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
