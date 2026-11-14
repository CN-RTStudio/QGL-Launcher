package main

import (
	"strings"
)

func lgScanConfigText(text string) (jndi, lookup, secret, remote, jdbc bool) {
	lower := strings.ToLower(text)
	for _, token := range lgJNDITokens {
		if strings.Contains(lower, token) {
			jndi = true
			break
		}
	}
	for _, token := range lgLookupTokens {
		if strings.Contains(lower, token) {
			lookup = true
			break
		}
	}
	for _, token := range lgSecretPatterns {
		if strings.Contains(lower, token) {
			secret = true
			break
		}
	}
	if strings.Contains(lower, "<socket") || strings.Contains(lower, "<jms") ||
		strings.Contains(lower, "syslog") || strings.Contains(lower, "httpappender") {
		remote = true
	}
	if strings.Contains(lower, "jdbc:") || strings.Contains(lower, "jdbcappender") {
		jdbc = true
	}
	return
}
