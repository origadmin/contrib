/*
 * Copyright (c) 2024 OrigAdmin. All rights reserved.
 */

// Package tz implements the functions, types, and interfaces for the module.
package tz

import (
	"testing"
)

func TestGenerateJSON(t *testing.T) {
	tests := []struct {
		name    string
		wantErr bool
	}{
		// TODO: Add test cases.
		{
			name: "test",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := GenerateJSON(); (err != nil) != tt.wantErr {
				t.Errorf("GenerateJSON() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestLocalLocation(t *testing.T) {
	tests := []struct {
		name string
		want string
	}{
		// TODO: Add test cases.
		{
			name: "test",
			want: "Asia/Shanghai",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := Location(); got != tt.want {
				t.Errorf("LocalLocation() = %v, want %v", got, tt.want)
			}
		})
	}
}
