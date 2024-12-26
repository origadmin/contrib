/*
 * Copyright (c) 2024 OrigAdmin. All rights reserved.
 */

// Package tz implements the functions, types, and interfaces for the module.
package tz

import (
	"reflect"
	"testing"
)

func TestTimeZonesFromFile(t *testing.T) {
	type args struct {
		filePath string
	}
	tests := []struct {
		name      string
		args      args
		want      []TimeZone
		wantTotal int
		wantErr   bool
	}{
		// TODO: Add test cases.
		{
			name: "test",
			args: args{
				filePath: "time_zone.csv",
			},
			want:      nil,
			wantTotal: 146523,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := TimeZonesFromCSV(tt.args.filePath)
			if (err != nil) != tt.wantErr {
				t.Errorf("TimeZonesFromCSV() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if len(got) != tt.wantTotal {
				t.Errorf("TimeZonesFromCSV() got = %v, want %v", len(got), tt.wantTotal)
			}
		})
	}
}

func TestTimeZoneFrom(t *testing.T) {
	type args struct {
		abbr   string
		offset int64
		dst    int64
	}
	tests := []struct {
		name    string
		args    args
		want    TimeZone
		wantErr bool
	}{
		{
			name: "test",
			args: args{
				abbr:   "CST",
				offset: 480 * 60,
				dst:    0,
			},
			want: TimeZone{
				Abbreviation: "CST",
				CountryCode:  "CN",
				Dst:          0,
				GmtOffset:    28800,
				ZoneName:     "Asia/Shanghai",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := TimeZoneFrom(tt.args.abbr, tt.args.offset, tt.args.dst)
			if (err != nil) != tt.wantErr {
				t.Errorf("TimeZoneFrom() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("TimeZoneFrom() got = %v, want %v", got, tt.want)
			}
		})
	}
}
