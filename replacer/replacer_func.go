/*
 * Copyright (c) 2024 OrigAdmin. All rights reserved.
 */

package replacer

import (
	"encoding/json"
	"os"
)

// ReplaceFileContent opens a file, replaces occurrences of ${name} with values from the map, and returns the result as []byte.
func ReplaceFileContent(path string, replacements map[string]string) ([]byte, error) {
	// Read the file content
	content, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	bytes := _globalReplacer.Replace(content, replacements)
	return bytes, nil
}

// ReplaceFileContentWithMatcher replaces occurrences of ${name} with values from the map
func ReplaceFileContentWithMatcher(path string, m Matcher) ([]byte, error) {
	content, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	replaced := m.Replace(string(content))
	return []byte(replaced), nil
}

// ReplaceObjectContent replaces occurrences of ${name} with values from the map
func ReplaceObjectContent(v any, replacements map[string]string) error {
	if v == nil {
		return nil
	}
	marshal, err := json.Marshal(v)
	if err != nil {
		return err
	}
	bytes := _globalReplacer.Replace(marshal, replacements)
	return json.Unmarshal(bytes, v)
}

// ReplaceObjectContentWithMatcher replaces occurrences of ${name} with values from the map
func ReplaceObjectContentWithMatcher(v any, m Matcher) error {
	if v == nil {
		return nil
	}
	marshal, err := json.Marshal(v)
	if err != nil {
		return err
	}
	replaced := m.Replace(string(marshal))
	return json.Unmarshal([]byte(replaced), v)
}
