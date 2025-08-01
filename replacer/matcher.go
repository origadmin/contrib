/*
 * Copyright (c) 2024 OrigAdmin. All rights reserved.
 */

package replacer

import (
	"bytes"
	"maps"
	"strings"

	"github.com/goexts/generic/settings"

	"github.com/origadmin/toolkits/codec"
	"github.com/origadmin/toolkits/errors"
)

// Matcher interface defines methods for matching and replacing strings.
type Matcher interface {
	Match(content string) (string, bool)
	Replace(content string) string
	ReplaceBytes(content []byte) []byte
	Replacement() map[string]string
}
type Match struct {
	offset      int
	sta         string
	end         string
	sep         string
	fold        bool
	replacement map[string]string
}

func (m Match) Replacement() map[string]string {
	return maps.Clone(m.replacement)
}

func (m Match) Match(content string) (string, bool) {
	cursor := 0
	for {
		// Find the next occurrence of `${`
		sta := strings.Index(content[cursor:], m.sta)
		if sta == -1 {
			// No more occurrences, write the remaining content and break
			break
		}

		// Find the closing `}`
		end := strings.Index(content[cursor+sta:], m.end)
		if end == -1 {
			// No closing brace found, write the remaining content and break
			break
		}
		// Extract the variable name
		args := content[cursor+sta+m.offset : cursor+sta+end]
		vars := strings.SplitN(args, m.sep, 2)
		skey := vars[0]
		// Check for Replacement in the map (case-insensitive)
		for key, value := range m.replacement {
			if defaultMatchFunc(skey, key, m.fold) {
				return value, true
			}
		}

		// Update the cursor position for the next iteration
		cursor = cursor + sta + end + 1
	}

	return "", false
}

func (m Match) Replace(content string) string {
	cursor := 0
	var sb strings.Builder

	for {
		// Find the next occurrence of `${`
		sta := strings.Index(content[cursor:], m.sta)
		if sta == -1 {
			sb.WriteString(content[cursor:])
			// No more occurrences, write the remaining content and break
			break
		}

		// Write the content before the found pattern
		sb.WriteString(content[cursor : cursor+sta])

		// Find the closing `}`
		end := strings.Index(content[cursor+sta:], m.end)
		if end == -1 {
			sb.WriteString(content[cursor+sta:])
			// No closing brace found, write the remaining content and break
			break
		}
		// Extract the variable name
		args := content[cursor+sta+m.offset : cursor+sta+end]
		// Check for Replacement in the map (case-insensitive)
		skey, sval, ok := strings.Cut(args, m.sep)
		found := false
		for key, value := range m.replacement {
			if value != "" && defaultMatchFunc(skey, key, m.fold) {
				sb.WriteString(value)
				found = true
				break
			}
		}
		if !found {
			if ok {
				sb.WriteString(sval)
			} else {
				sb.WriteString(m.sta + skey + m.end)
			}
		}
		// Update the cursor position for the next iteration
		cursor = cursor + sta + end + 1
	}

	return sb.String()
}

// ReplaceBytes replaces the content with the provided replacements.
func (m Match) ReplaceBytes(content []byte) []byte {
	cursor := 0
	var bb bytes.Buffer

	for {
		// Find the next occurrence of `${`
		sta := bytes.Index(content[cursor:], []byte(m.sta))
		if sta == -1 {
			bb.Write(content[cursor:])
			// No more occurrences, write the remaining content and break
			break
		}

		// Write the content before the found pattern
		bb.Write(content[cursor : cursor+sta])

		// Find the closing `}`
		end := bytes.Index(content[cursor+sta:], []byte(m.end))
		if end == -1 {
			bb.Write(content[cursor+sta:])
			// No closing brace found, write the remaining content and break
			break
		}
		// Extract the variable name
		args := content[cursor+sta+len(m.sta) : cursor+sta+end]
		// Check for Replacement in the map (case-insensitive)
		skey, sval, ok := bytes.Cut(args, []byte(m.sep))
		found := false
		for key, value := range m.replacement {
			if value != "" && defaultMatchFunc(string(skey), key, m.fold) {
				bb.WriteString(value)
				found = true
				break
			}
		}
		if !found {
			if ok {
				bb.Write(sval)
			} else {
				bb.Write([]byte(m.sta))
				bb.Write(skey)
				bb.Write([]byte(m.end))
			}
		}
		// Update the cursor position for the next iteration
		cursor = cursor + sta + end + len(m.end)
	}

	return bb.Bytes()
}

// NewMatch creates a new Match with the provided replacements.
func NewMatch(replacements map[string]string, ss ...MatchSetting) *Match {
	m := settings.Apply(&Match{
		replacement: replacements,
		sta:         defaultMatchStartKeyword,
		end:         defaultMatchEndKeyword,
		sep:         defaultMatchSeparatorKeyword,
	}, ss)

	m.offset = len(m.sta)
	return m
}

// NewMatchFile creates a new Match with the provided replacements from a JSON file.
func NewMatchFile(path string, ss ...MatchSetting) (*Match, error) {
	var replacements map[string]string
	err := codec.DecodeFromFile(path, &replacements)
	if err != nil {
		return nil, errors.Wrap(err, "NewMatchFile")
	}
	return NewMatch(replacements, ss...), nil
}

func defaultMatchFunc(src, key string, fold bool) bool {
	return fold && strings.EqualFold(key, src) || key == src
}
