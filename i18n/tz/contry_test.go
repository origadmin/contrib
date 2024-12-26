/*
 * Copyright (c) 2024 OrigAdmin. All rights reserved.
 */

// Package tz implements the functions, types, and interfaces for the module.
package tz

import (
	"testing"
)

func TestCountriesFromFile(t *testing.T) {
	type args struct {
		filePath string
	}
	tests := []struct {
		name      string
		args      args
		want      []Country
		wantTotal int
		wantErr   bool
	}{
		// TODO: Add test cases.
		{
			name:      "test",
			args:      args{filePath: "country.csv"},
			wantTotal: 247,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := CountriesFromCSV(tt.args.filePath)
			if (err != nil) != tt.wantErr {
				t.Errorf("CountriesFromCSV() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if len(got) != tt.wantTotal {
				t.Errorf("CountriesFromCSV() got = %v, want %v", len(got), tt.wantTotal)
			}
		})
	}
}
