/*
 * Copyright (c) 2024 OrigAdmin. All rights reserved.
 */

package replacer

import (
	"os"
	"testing"
)

// Successfully replaces all occurrences of patterns with corresponding values from the map
func TestReplaceAllPatterns(t *testing.T) {
	// Arrr, let's set sail with some replacements!
	filePath := "testfile.txt"
	content := "Hello, @{name}! Welcome to @{place}."
	os.WriteFile(filePath, []byte(content), 0644)
	replacements := map[string]string{"Name": "Captain", "Place": "the ship"}

	result, err := ReplaceFileContent(filePath, replacements)
	if err != nil {
		t.Fatalf("Expected no error, but got %v", err)
	}

	expected := "Hello, Captain! Welcome to the ship."
	if string(result) != expected {
		t.Errorf("Expected %s, but got %s", expected, result)
	}
}

// Returns the original content if no patterns are found
func TestNoPatternsFound(t *testing.T) {
	// Avast! No patterns to be found here!
	filePath := "testfile.txt"
	content := "Hello, world!"
	os.WriteFile(filePath, []byte(content), 0644)
	replacements := map[string]string{"name": "Captain"}

	result, err := ReplaceFileContent(filePath, replacements)
	if err != nil {
		t.Fatalf("Expected no error, but got %v", err)
	}

	if string(result) != content {
		t.Errorf("Expected %s, but got %s", content, result)
	}
}

// Handles case-insensitive replacements correctly
func TestCaseInsensitiveReplacements(t *testing.T) {
	// Yarrr! Case be no match for us!
	filePath := "testfile.txt"
	content := "Ahoy, @{Name}!"
	os.WriteFile(filePath, []byte(content), 0644)
	replacements := map[string]string{"name": "Matey"}

	result, err := ReplaceFileContent(filePath, replacements)
	if err != nil {
		t.Fatalf("Expected no error, but got %v", err)
	}

	expected := "Ahoy, Matey!"
	if string(result) != expected {
		t.Errorf("Expected %s, but got %s", expected, result)
	}
}

// Handles files with no patterns gracefully
func TestNoPatternsInFile(t *testing.T) {
	// Shiver me timbers! No patterns aboard this vessel!
	filePath := "testfile.txt"
	content := "Just some plain text."
	os.WriteFile(filePath, []byte(content), 0644)
	replacements := map[string]string{"name": "Pirate"}

	result, err := ReplaceFileContent(filePath, replacements)
	if err != nil {
		t.Fatalf("Expected no error, but got %v", err)
	}

	if string(result) != content {
		t.Errorf("Expected %s, but got %s", content, result)
	}
}

// Manages patterns with no corresponding Replacement in the map
func TestNoReplacementForPattern(t *testing.T) {
	// Arrr! No treasure for this pattern!
	filePath := "testfile.txt"
	content := "Ahoy, @{unknown}!"
	os.WriteFile(filePath, []byte(content), 0644)
	replacements := map[string]string{"name": "Pirate"}

	result, err := ReplaceFileContent(filePath, replacements)
	if err != nil {
		t.Fatalf("Expected no error, but got %v", err)
	}

	expected := "Ahoy, @{unknown}!"
	if string(result) != expected {
		t.Errorf("Expected %s, but got %s", expected, result)
	}
}

// Deals with patterns that have no closing brace
func TestPatternWithoutClosingBrace(t *testing.T) {
	// Blimey! A pattern adrift without a closing brace!
	filePath := "testfile.txt"
	content := "Ahoy, @{name"
	os.WriteFile(filePath, []byte(content), 0644)
	replacements := map[string]string{"name": "Pirate"}

	result, err := ReplaceFileContent(filePath, replacements)
	if err != nil {
		t.Fatalf("Expected no error, but got %v", err)
	}

	if string(result) != content {
		t.Errorf("Expected %s, but got %s", content, result)
	}
}

// Deals with patterns that have no closing brace
func TestWithDefaultValue(t *testing.T) {
	// Blimey! A pattern adrift without a closing brace!
	filePath := "testfile.txt"
	content := "Ahoy, @{name=Pirate}"
	expected := "Ahoy, Pirate"
	os.WriteFile(filePath, []byte(content), 0644)
	replacements := map[string]string{}

	result, err := ReplaceFileContent(filePath, replacements)
	if err != nil {
		t.Fatalf("Expected no error, but got %v", err)
	}

	if string(result) != expected {
		t.Errorf("Expected %s, but got %s", expected, result)
	}
	t.Logf("Result: %s", result)
}

// Processes empty files without errors
func TestEmptyFile(t *testing.T) {
	// Aye! An empty sea of bytes!
	filePath := "emptyfile.txt"
	os.WriteFile(filePath, []byte(""), 0644)
	replacements := map[string]string{"name": "Pirate"}

	result, err := ReplaceFileContent(filePath, replacements)
	if err != nil {
		t.Fatalf("Expected no error, but got %v", err)
	}

	if len(result) != 0 {
		t.Errorf("Expected empty result, but got %s", result)
	}
}
