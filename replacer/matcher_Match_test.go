package replacer

import (
	"testing"
)

// Returns IP and true when name matches a host key
func TestMatchReturnsIPAndTrue(t *testing.T) {
	// Arrr, let's set sail with a map of hosts!
	hosts := map[string]string{"pirate": "192.168.1.1"}
	hostname := NewMatch(nil, WithMatchHostMap(hosts), WithMatchSta("@"), WithMatchEnd(":"))

	ip, ok := hostname.Match("@pirate:9874")

	if !ok || ip != "192.168.1.1" {
		t.Errorf("Expected IP '192.168.1.1' and true, got %s and %v", ip, ok)
	}
}

// Returns false when hosts map is nil
func TestMatchReturnsFalseWhenHostsNil(t *testing.T) {
	// Avast! No hosts in sight!
	hostname := NewMatch(nil, WithMatchSta("@"), WithMatchEnd(":"))

	_, ok := hostname.Match("@ghost:9874")

	if ok {
		t.Error("Expected false, but got true")
	}
}

// Correctly processes name with default prefix and suffix
func TestMatchWithDefaultPrefixSuffix(t *testing.T) {
	// Yo ho ho! Testing with default prefix and suffix!
	hosts := map[string]string{"captain": "10.0.0.1"}
	hostname := NewMatch(nil, WithMatchHostMap(hosts), WithMatchSta("@"), WithMatchEnd(":"))

	ip, ok := hostname.Match("@captain:9874")

	if !ok || ip != "10.0.0.1" {
		t.Errorf("Expected IP '10.0.0.1' and true, got %s and %v", ip, ok)
	}
}

// Correctly processes name with default prefix and suffix
func TestMatchWithDefault(t *testing.T) {
	// Yo ho ho! Testing with default prefix and suffix!
	hosts := map[string]string{}
	hostname := NewMatch(nil, WithMatchHostMap(hosts), WithMatchSta("@"), WithMatchEnd(":"))

	ip, ok := hostname.Match("@captain::9874")

	if ok {
		t.Errorf("Expected IP '10.0.0.1' and true, got %s and %v", ip, ok)
	}
}

// Handles empty string as name input
func TestMatchHandlesEmptyString(t *testing.T) {
	// Shiver me timbers! An empty name it be!
	hosts := map[string]string{"empty": "127.0.0.1"}
	hostname := NewMatch(nil, WithMatchHostMap(hosts), WithMatchSta("@"), WithMatchEnd(":"))

	_, ok := hostname.Match("")

	if ok {
		t.Error("Expected false, but got true")
	}
}

// Handles name with no matching host key
func TestMatchNoMatchingHostKey(t *testing.T) {
	// Arrr, no matchin' key in these waters!
	hosts := map[string]string{"parrot": "172.16.0.1"}
	hostname := NewMatch(nil, WithMatchHostMap(hosts), WithMatchSta("@"), WithMatchEnd(":"))

	_, ok := hostname.Match("@kraken:9874")

	if ok {
		t.Error("Expected false, but got true")
	}
}

// Handles name with only prefix or suffix
func TestMatchWithOnlyPrefixOrSuffix(t *testing.T) {
	// Aye, testing with only a prefix or suffix!
	hosts := map[string]string{"matey": "192.168.0.2"}
	hostname := NewMatch(nil, WithMatchHostMap(hosts), WithMatchSta("@"), WithMatchEnd(":"))

	v1, okPrefix := hostname.Match("@matey")
	v2, okSuffix := hostname.Match("matey:")
	if okPrefix {
		t.Error("Expected true for both prefix-only, but got false", v1)
	}
	if okSuffix {
		t.Error("Expected false for both prefix-only and suffix-only, but got true", v2)
	}
}

// Handles hosts map with multiple entries
func TestMatchMultipleEntries(t *testing.T) {
	// Yo ho ho! Multiple entries on the horizon!
	hosts := map[string]string{
		"blackbeard": "192.168.2.1",
		"longjohn":   "192.168.2.2",
	}
	hostname := NewMatch(nil, WithMatchHostMap(hosts), WithMatchSta("@"), WithMatchEnd(":"))

	ip, ok := hostname.Match("@blackbeard:9874")

	if !ok || ip != "192.168.2.1" {
		t.Errorf("Expected IP '192.168.2.1' and true, got %s and %v", ip, ok)
	}

	ip, ok = hostname.Match("@longjohn::9874")

	if !ok || ip != "192.168.2.2" {
		t.Errorf("Expected IP '192.168.2.2' and true, got %s and %v", ip, ok)
	}
}

func TestMatchHost(t *testing.T) {
	//hosts := map[string]string{
	//	"blackbeard": "192.168.2.1",
	//	"longjohn":   "192.168.2.2",
	//}
	hostname := New(nil)

	ip := hostname.ReplaceString("${consul_address:127.0.0.1:8500}", nil)
	if ip != "127.0.0.1:8500" {
		t.Errorf("Expected IP '127.0.0.1:8500' and true, got %s", ip)
	}
}
