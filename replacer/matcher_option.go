/*
 * Copyright (c) 2024 OrigAdmin. All rights reserved.
 */

package replacer

import (
	"maps"
	"net"
	"strings"
)

type MatchSetting = func(*Match)

// WithMatchSta returns a new Matcher instance with replacer start keyword.
func WithMatchSta(sta string) MatchSetting {
	return func(r *Match) {
		r.sta = sta
	}
}

// WithMatchEnd returns a new Matcher instance with replacer end keyword.
func WithMatchEnd(end string) MatchSetting {
	return func(r *Match) {
		r.end = end
	}
}

// WithMatchFold returns a new Matcher instance with case-insensitive matching.
func WithMatchFold(fold bool) MatchSetting {
	return func(r *Match) {
		r.fold = fold
	}
}

// WithMatchHosts Parse the name and return the corresponding IP address
func WithMatchHosts(list []string, sep string) MatchSetting {
	hosts := make(map[string]string)
	for i := range list {
		nameip := strings.Split(list[i], sep)
		if len(nameip) != 2 {
			continue
		}
		if ip := net.ParseIP(nameip[1]); ip != nil {
			hosts[nameip[0]] = nameip[1]
		}
	}
	return func(h *Match) {
		if h.replacement == nil {
			h.replacement = hosts
			return
		}
		maps.Copy(h.replacement, hosts)
	}
}

// WithMatchHostMap Parse the name and return the corresponding IP address
func WithMatchHostMap(hosts map[string]string) MatchSetting {
	return func(h *Match) {
		if h.replacement == nil {
			h.replacement = hosts
			return
		}
		maps.Copy(h.replacement, hosts)
	}
}

// WithMatchSeparator returns a new Matcher instance with replacer separator
func WithMatchSeparator(sep string) MatchSetting {
	return func(h *Match) {
		h.sep = sep
	}
}
