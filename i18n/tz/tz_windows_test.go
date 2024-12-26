/*
 * Copyright (c) 2024 OrigAdmin. All rights reserved.
 */

// Package tz implements the functions, types, and interfaces for the module.
package tz

import (
	"reflect"
	"testing"

	"github.com/origadmin/toolkits/codec"
)

func TestWindowsZonesFromXML(t *testing.T) {
	type args struct {
		filePath string
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		// TODO: Add test cases.
		{
			name: "test",
			args: args{
				filePath: "windows/windowsZones.xml",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := WindowsZonesFromXMLToJSON(tt.args.filePath)
			if (err != nil) != tt.wantErr {
				t.Errorf("WindowsZonesFromXML() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

		})
	}
}

func TestWindowsZonesFromJSON(t *testing.T) {
	type args struct {
		filePath string
	}
	tests := []struct {
		name    string
		args    args
		want    WindowsZones
		wantErr bool
	}{
		// TODO: Add test cases.
		{
			name: "test",
			args: args{
				filePath: "windows/windows_zones.json",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := WindowsZonesFromJSON(tt.args.filePath)
			if (err != nil) != tt.wantErr {
				t.Errorf("WindowsZonesFromJSON() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("WindowsZonesFromJSON() got = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestSaveNewTimeZonesToJSON(t *testing.T) {
	var supplementalData SupplementalData
	err := codec.DecodeFromFile("windows/windowsZones.json", &supplementalData)
	if err != nil {
		return
	}
	type args struct {
		timeZones []TimeZone
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		// TODO: Add test cases.
		{
			name: "test",
			args: args{
				timeZones: FixTimeZoneFromWindowsZones(supplementalData.WindowsZones),
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := SaveNewTimeZonesToJSON(tt.args.timeZones); (err != nil) != tt.wantErr {
				t.Errorf("SaveNewTimeZonesToJSON() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestTimeZoneToTimeZoneMap(t *testing.T) {
	type args struct {
		mapfile string
	}
	tests := []struct {
		name string
		args args
	}{
		// TODO: Add test cases.
		{
			name: "test",
			args: args{
				mapfile: "map_zones.json",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			TimeZoneToTimeZoneMap(tt.args.mapfile)
		})
	}
}
