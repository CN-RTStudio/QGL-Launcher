package main

import (
	"strings"
	"time"
)

func ppStaleExpiry(raw string, now time.Time) bool {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return true
	}
	layouts := []string{time.RFC3339, "2006-01-02 15:04:05 -0700", "2006-01-02T15:04:05.999999999Z"}
	for _, layout := range layouts {
		ts, err := time.Parse(layout, raw)
		if err == nil {
			return now.Sub(ts) > ppMaxStaleDays*24*time.Hour
		}
	}
	return true
}
