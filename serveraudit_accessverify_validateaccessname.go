package main

import (
	"fmt"
	"sort"
	"strings"
	"unicode/utf8"
)

func validateAccessName(raw string) (string, string) {
	value := strings.TrimSpace(raw)
	if value == "" {
		return accessReasonBadEntry, "缺少 name 字段"
	}
	if utf8.RuneCountInString(value) > accessMaxNameRunes {
		return accessReasonBadEntry, fmt.Sprintf("name 超过 %d 字符", accessMaxNameRunes)
	}
	if containsControlByte(value) {
		return accessReasonBadEntry, "name 含控制字符"
	}
	if strings.ContainsAny(value, "/\\:\"'") {
		return accessReasonBadEntry, "name 含路径或引号字符"
	}
	return "", ""
}

func (a ServerAccessAudit) Blocking() bool {
	for _, finding := range a.Findings {
		if finding.Blocking {
			return true
		}
	}
	return false
}
func (a ServerAccessAudit) HasWarnings() bool {
	for _, finding := range a.Findings {
		if !finding.Blocking {
			return true
		}
	}
	return false
}
func (a ServerAccessAudit) Codes() []string {
	seen := map[string]bool{}
	codes := []string{}
	for _, finding := range a.Findings {
		if seen[finding.Reason] {
			continue
		}
		seen[finding.Reason] = true
		codes = append(codes, finding.Reason)
	}
	sort.Strings(codes)
	return codes
}
