package replacer

import (
	"testing"
)

// Replaces name with IP when prefix and suffix match
func TestReplaceNameWithIPWhenPrefixAndSuffixMatch(t *testing.T) {
	// Arrr, let's see if the name be replaced with the IP when the prefix and suffix match!
	hosts := map[string]string{"pirate": "192.168.1.1"}
	h := NewMatch(nil, WithMatchHostMap(hosts), WithMatchSta("@"), WithMatchEnd(":"))
	name := "@pirate::9874"
	expected := "192.168.1.1:9874"
	result := h.Replace(name)
	if result != expected {
		t.Errorf("Expected %s, but got %s", expected, result)
	}

}

// Returns original name if no match is found
func TestReturnsOriginalNameIfNoMatchFound(t *testing.T) {
	// Avast! If no match be found, the original name should stay afloat!
	hosts := map[string]string{"pirate": "192.168.1.1"}
	h := NewMatch(hosts, WithMatchSta("@"), WithMatchEnd(":"))
	name := "@captain:"
	expected := "@captain:"
	result := h.Replace(name)
	if result != expected {
		t.Errorf("Expected %s, but got %s", expected, result)
	}
}

// Handles valid host map with correct IP Replacement
func TestHandlesValidHostMapWithCorrectIPReplacement(t *testing.T) {
	// Shiver me timbers! Let's see if the map handles the IP Replacement correctly!
	hosts := map[string]string{"pirate": "192.168.1.1"}
	h := NewMatch(nil, WithMatchHostMap(hosts), WithMatchSta("@"), WithMatchEnd(":"))
	name := "@pirate:"
	expected := "192.168.1.1"
	result := h.Replace(name)
	if result != expected {
		t.Errorf("Expected %s, but got %s", expected, result)
	}
}

// Returns original name when hosts map is nil
func TestReturnsOriginalNameWhenHostsMapIsNil(t *testing.T) {
	// Arrr, when the map be empty, the name should stay as it be!
	h := NewMatch(nil, WithMatchSta("@"), WithMatchEnd(":"))
	name := "@pirate:"
	expected := "@pirate:"
	result := h.Replace(name)
	if result != expected {
		t.Errorf("Expected %s, but got %s", expected, result)
	}
}

// Handles names without prefix or suffix correctly
func TestHandlesNamesWithoutPrefixOrSuffixCorrectly(t *testing.T) {
	// Yo ho ho! Names without prefix or suffix should sail through unchanged!
	hosts := map[string]string{"pirate": "192.168.1.1"}
	h := NewMatch(nil, WithMatchHostMap(hosts), WithMatchSta("@"), WithMatchEnd(":"))
	name := "pirate"
	expected := "pirate"
	result := h.Replace(name)
	if result != expected {
		t.Errorf("Expected %s, but got %s", expected, result)
	}
}

// Manages empty string input gracefully
func TestManagesEmptyStringInputGracefully(t *testing.T) {
	// Blimey! An empty string should not cause a mutiny!
	hosts := map[string]string{"pirate": "192.168.1.1"}
	h := NewMatch(nil, WithMatchHostMap(hosts), WithMatchSta("@"), WithMatchEnd(":"))
	name := ""
	expected := ""
	result := h.Replace(name)
	if result != expected {
		t.Errorf("Expected %s, but got %s", expected, result)
	}
}

// Deals with malformed host entries in map
func TestDealsWithMalformedHostEntriesInMap(t *testing.T) {
	// Arrr matey! Malformed entries should not sink the ship!
	hosts := map[string]string{"pirate": ""}
	h := NewMatch(nil, WithMatchHostMap(hosts), WithMatchSta("@"), WithMatchEnd(":"))
	name := "@pirate:"
	expected := "@pirate:"
	result := h.Replace(name)
	if result != expected {
		t.Errorf("Expected %s, but got %s", expected, result)
	}
}
