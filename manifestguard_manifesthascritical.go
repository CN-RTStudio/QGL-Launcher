package main

import (
	"fmt"
	"strings"
)

func manifestHasCritical(findings []ManifestFinding) bool {
	for i := range findings {
		if findings[i].Severity == manifestCritical {
			return true
		}
	}
	return false
}
func manifestCriticalError(findings []ManifestFinding) error {
	n := 0
	fields := make([]string, 0, 8)
	for i := range findings {
		if findings[i].Severity != manifestCritical {
			continue
		}
		n++
		if len(fields) < 8 {
			fields = append(fields, findings[i].Field)
		}
	}
	if n == 0 {
		return nil
	}
	return fmt.Errorf("版本清单存在 %d 处严重安全问题，已拒绝下载（涉及字段: %s）", n, strings.Join(fields, ", "))
}

func safeVersionName(raw string) string {
	s := strings.TrimSpace(raw)
	if s == "" || len(s) > 256 {
		return ""
	}
	if s == "." || s == ".." || strings.ContainsAny(s, `/\:`) {
		return ""
	}
	for _, r := range s {
		if r == 0 || r < 0x20 {
			return ""
		}
	}
	return s
}
