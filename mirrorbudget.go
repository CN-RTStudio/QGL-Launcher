package main

import (
	"strings"
	"time"
)

const (
	mirrorMaxAttempts    = 8
	mirrorFallbackBase   = 500 * time.Millisecond
	mirrorFallbackCap    = 5 * time.Second
	mirrorFallbackBudget = 90 * time.Second
)

type mirrorPlan struct {
	URLs   []string
	Start  time.Time
	Budget time.Duration
}

func planMirrorAttempts(urls []string, now time.Time) mirrorPlan {
	seen := make(map[string]bool, len(urls))
	clean := make([]string, 0, len(urls))
	for _, u := range urls {
		u = strings.TrimSpace(u)
		if u == "" || seen[u] {
			continue
		}
		seen[u] = true
		clean = append(clean, u)
		if len(clean) >= mirrorMaxAttempts {
			break
		}
	}
	return mirrorPlan{URLs: clean, Start: now, Budget: mirrorFallbackBudget}
}

func (p mirrorPlan) expired(now time.Time) bool {
	if p.Budget <= 0 {
		return false
	}
	return now.Sub(p.Start) >= p.Budget
}

func mirrorFallbackDelay(attempt int) time.Duration {
	if attempt < 0 {
		attempt = 0
	}
	d := time.Duration(attempt+1) * mirrorFallbackBase
	if d > mirrorFallbackCap {
		return mirrorFallbackCap
	}
	return d
}
