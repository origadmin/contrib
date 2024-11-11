package replacer

import (
	"testing"
)

// Successfully replaces placeholders in JSON-encoded objects with provided values
func TestReplacePlaceholdersInJSON(t *testing.T) {
	// Arrr! Let's see if we can replace the treasure map's X marks!
	type TreasureMap struct {
		Location string `json:"location"`
	}
	mapData := TreasureMap{Location: "@{location}"}
	replacements := map[string]string{"location": "Isla de Muerta"}

	err := ReplaceObjectContent(&mapData, replacements)
	if err != nil {
		t.Fatalf("Expected no error, but got %v", err)
	}

	if mapData.Location != "Isla de Muerta" {
		t.Errorf("Expected location to be 'Isla de Muerta', but got %s", mapData.Location)
	}
}

// Handles JSON marshaling and unmarshaling without errors for valid input
func TestJSONMarshalingUnmarshaling(t *testing.T) {
	// Ahoy! Let's make sure our ship's log can be read and written without sinking!
	type ShipLog struct {
		Captain string `json:"captain"`
	}
	logData := ShipLog{Captain: "Jack Sparrow"}
	replacements := map[string]string{}

	err := ReplaceObjectContent(&logData, replacements)
	if err != nil {
		t.Fatalf("Expected no error, but got %v", err)
	}

	if logData.Captain != "Jack Sparrow" {
		t.Errorf("Expected captain to be 'Jack Sparrow', but got %s", logData.Captain)
	}
}

// Uses default replacement settings when no specific settings are provided
func TestDefaultReplacementSettings(t *testing.T) {
	// Avast! Let's see if the default settings are as trusty as a pirate's compass!
	type Compass struct {
		Direction string `json:"direction"`
	}
	compassData := Compass{Direction: "@{direction}"}
	replacements := map[string]string{"direction": "North"}

	err := ReplaceObjectContent(&compassData, replacements)
	if err != nil {
		t.Fatalf("Expected no error, but got %v", err)
	}

	if compassData.Direction != "North" {
		t.Errorf("Expected direction to be 'North', but got %s", compassData.Direction)
	}
}

// Handles empty replacement maps without altering the original object
func TestEmptyReplacementMap(t *testing.T) {
	// Shiver me timbers! Let's see if an empty map leaves our treasure untouched!
	type Treasure struct {
		Gold string `json:"gold"`
	}
	treasureData := Treasure{Gold: "1000 doubloons"}
	replacements := map[string]string{}

	err := ReplaceObjectContent(&treasureData, replacements)
	if err != nil {
		t.Fatalf("Expected no error, but got %v", err)
	}

	if treasureData.Gold != "1000 doubloons" {
		t.Errorf("Expected gold to be '1000 doubloons', but got %s", treasureData.Gold)
	}
}

// Manages JSON objects with no placeholders gracefully
func TestNoPlaceholdersInJSON(t *testing.T) {
	// Arrr! Let's see if our map sails smoothly without any X marks!
	type Map struct {
		Island string `json:"island"`
	}
	mapData := Map{Island: "Tortuga"}
	replacements := map[string]string{"location": "Isla de Muerta"}

	err := ReplaceObjectContent(&mapData, replacements)
	if err != nil {
		t.Fatalf("Expected no error, but got %v", err)
	}

	if mapData.Island != "Tortuga" {
		t.Errorf("Expected island to be 'Tortuga', but got %s", mapData.Island)
	}

}

// Processes objects with deeply nested structures
func TestDeeplyNestedStructures(t *testing.T) {
	// Yo ho ho! Let's dive deep into the nested seas of JSON!
	type Crew struct {
		Captain struct {
			Name string `json:"name"`
		} `json:"captain"`
		FirstMate struct {
			Name string `json:"name"`
		} `json:"first_mate"`
	}

	crewData := Crew{
		Captain: struct {
			Name string `json:"name"`
		}(struct{ Name string }{Name: "@{captain_name}"}),
		FirstMate: struct {
			Name string `json:"name"`
		}(struct{ Name string }{Name: "@{first_mate_name}"}),
	}

	replacements := map[string]string{
		"captain_name":    "Blackbeard",
		"first_mate_name": "Long John Silver",
	}

	err := ReplaceObjectContent(&crewData, replacements)
	if err != nil {
		t.Fatalf("Expected no error, but got %v", err)
	}

	if crewData.Captain.Name != "Blackbeard" || crewData.FirstMate.Name != "Long John Silver" {
		t.Errorf("Expected names to be 'Blackbeard' and 'Long John Silver', but got '%s' and '%s'", crewData.Captain.Name, crewData.FirstMate.Name)
	}
}

// Handles invalid JSON input by returning an error
func TestInvalidJSONInput(t *testing.T) {
	// Blimey! Let's see how we handle a shipwreck of a JSON!
	var invalidJSON interface{}

	replacements := map[string]string{"key": "value"}

	err := ReplaceObjectContent(&invalidJSON, replacements)

	if err != nil {
		t.Fatalf("Expected an error for invalid JSON input, but got %v", err)
	}
}
