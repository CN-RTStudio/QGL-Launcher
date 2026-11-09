package main

import "strings"

const bmclMirrorBase = "https://bmclapi2.bangbang93.com"

type urlPrefixRule struct {
	from string
	to   string
}

func rewriteURLPrefixes(raw string, rules []urlPrefixRule) string {
	out := raw
	for _, rule := range rules {
		if rule.from == "" {
			continue
		}
		if !strings.HasPrefix(out, rule.from) {
			continue
		}
		if mirrorRuleEndsAtHost(rule.from) && !mirrorPrefixEndsAtHostBoundary(out[len(rule.from):]) {
			continue
		}
		out = strings.Replace(out, rule.from, rule.to, 1)
	}
	return out
}
func mirrorRuleEndsAtHost(from string) bool {
	idx := strings.Index(from, "://")
	if idx < 0 {
		return false
	}
	rest := from[idx+3:]
	return !strings.ContainsAny(rest, "/?#")
}
