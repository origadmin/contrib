//go:build unix

/*
 * Copyright (c) 2024 OrigAdmin. All rights reserved.
 */

// Package tz implements the functions, types, and interfaces for the module.
package tz

import (
	"fmt"
	"os"
	"strings"
)

func location() string {
	bytes, err := os.ReadFile("/etc/timezone")
	if err == nil && len(bytes) > 0 {
		return string(bytes)
	}
	linkPath := "/etc/localtime"
	targetPath, err := os.Readlink(linkPath)
	if err != nil {
		return defaultTimeZone
	}

	tzParts := strings.Split(targetPath, "/")
	if len(tzParts) < 3 {
		return defaultTimeZone
	}

	continent, country := tzParts[len(tzParts)-2], tzParts[len(tzParts)-1]
	timezone := fmt.Sprintf("%s/%s", continent, country)
	return timezone
}
