package main

import (
	"fmt"
	"strings"
)

func isBlocked(flag string) bool {
	for _, b := range blockedJvmFlags {
		if strings.HasPrefix(flag, b) {
			return true
		}
	}
	return false
}

// IsKnownJvmFlag 报告一个标志是否在已知/允许清单里。
func IsKnownJvmFlag(flag string) bool {
	if isBlocked(flag) {
		return false
	}
	for _, l := range loggedJvmFlags {
		if strings.HasPrefix(flag, l) {
			return true
		}
	}
	// 无 - 开头的当类路径参数放过。
	return !strings.HasPrefix(flag, "-")
}

// FilterJvmFlags 直接返回安全子集，便于调用方使用。
func FilterJvmFlags(in []string) []string {
	blocked, passed := AuditJvmFlags(in)
	if len(blocked) > 0 {
		// 调用方应另行记录；这里只过滤。
		_ = blocked
	}
	return passed
}

// ErrBlockedJvmFlags 汇总错误（需要硬拒绝时用）。
func ErrBlockedJvmFlags(blocked []string) error {
	if len(blocked) == 0 {
		return nil
	}
	return fmt.Errorf("blocked jvm flags: %s", strings.Join(blocked, ", "))
}
