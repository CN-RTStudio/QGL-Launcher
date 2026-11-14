package main

import (
	"strings"
	"time"
)

func validateWorldName(name string) (string, string) {
	trimmed := strings.TrimSpace(name)
	if reason := auditComponent(trimmed, maxWorldNameLen); reason != nameRejectNone {
		return "", reason
	}
	return trimmed, nameRejectNone
}
func validateWorldStamp(stamp string) bool {
	if len(stamp) != worldStampLen || stamp[8] != '-' {
		return false
	}
	t, err := time.Parse(worldStampLayout, stamp)
	if err != nil {
		return false
	}
	return t.Format(worldStampLayout) == stamp
}
