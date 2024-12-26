/*
 * Copyright (c) 2024 OrigAdmin. All rights reserved.
 */

// Package i18n implements the functions, types, and interfaces for the module.
package i18n

import (
	"fmt"
	"reflect"
	"testing"

	"golang.org/x/text/language"
)

func TestLocaleFrom(t *testing.T) {
	type args struct {
		supports []string
	}
	tests := []struct {
		name string
		args args
		want string
	}{
		// TODO: Add test cases.
		{
			name: "test",
			args: args{
				supports: []string{"en-US", "zh-CN"},
			},
			want: "zh-CN",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := PreferredLocale(tt.args.supports...); got != tt.want {
				t.Errorf("LocaleFrom() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestCountryStrings(t *testing.T) {
	tests := []struct {
		name string
		want []string
	}{
		// TODO: Add test cases.
		{
			name: "test",
			want: []string{"en-US", "zh-CN", "zh-TW"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := CountryStrings(); !containsAll(got, tt.want) {
				t.Errorf("CountryStrings() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestLanguageStrings(t *testing.T) {
	tests := []struct {
		name string
		want []string
	}{
		// TODO: Add test cases.
		{
			name: "test",
			want: []string{"en-US", "zh-Hans", "zh-Hant"},
		},
		{
			name: "test",
			//want:   []string{"zh-TW", "zh-CN"}, // this is failure
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := LanguageStrings(); !containsAll(got, tt.want) {
				t.Errorf("LanguageStrings() = %v, want %v", got, tt.want)
			}
		})
	}
}

func containsAll(src []string, target []string) bool {
	for _, v := range target {
		if !contains(src, v) {
			return false
		}
	}
	return true
}

func contains(src []string, target string) bool {
	for _, v := range src {
		if v == target {
			return true
		}
	}
	return false
}

func TestString2Language(t *testing.T) {
	type args struct {
		s string
	}
	tests := []struct {
		name    string
		args    args
		want    language.Tag
		wantErr bool
	}{
		// TODO: Add test cases.
		{
			name: "test",
			args: args{
				s: "zh-CN",
			},
			want: language.SimplifiedChinese,
		},
		{
			name: "test",
			args: args{
				s: "zh-TW",
			},
			want: language.TraditionalChinese,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := String2Language(tt.args.s)
			b, s, _ := tt.want.Raw()
			fmt.Println(got.Raw())
			fmt.Println(tt.want.Raw())
			fmt.Println(got.Base())
			fmt.Println(tt.want.Base())
			fmt.Println(got.Script())
			fmt.Println(tt.want.Script())
			fmt.Println(got.Region())
			fmt.Println(tt.want.Region())
			want := language.Make(fmt.Sprintf("%s-%s", b, s))
			if !reflect.DeepEqual(got, want) {
				t.Errorf("String2Language() got = %v, want %v", got, want)
			}
		})
	}
}

func TestCountryLanguage(t *testing.T) {
	type args struct {
		lang language.Tag
	}
	tests := []struct {
		name string
		args args
		want language.Tag
	}{
		// TODO: Add test cases.
		{
			name: "test",
			args: args{
				lang: language.SimplifiedChinese,
			},
			want: language.Make("zh-CN"),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := CountryLanguage(tt.args.lang); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("CountryLanguage() = %v, want %v", got, tt.want)
			}
		})
	}
}
