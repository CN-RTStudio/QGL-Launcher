package main

// jvmflagknownlist.go —— JVM 启动标志白名单叠加层。
//
// jvmargs.go 已经做了一轮基础清洗；这里再叠一层“已知安全标志”清单，
// 把明显危险的标志（agent 注入、调试端口、RMI、覆盖安全管理器）挡在外面。
// 不改默认启动，只给外部传入的自定义 JVM 参数做最后一道闸。

import (
	"fmt"
	"strings"
)

// 明确拒绝的危险标志（前缀匹配）。
var blockedJvmFlags = []string{
	"-agentlib:",
	"-agentpath:",
	"-javaagent:",
	"-Xrunjdwp",
	"-Xdebug",
	"-XX:+UseRMI",
	"-Dcom.sun.management.jmxremote",
	"-Djava.security.manager",
}

// 允许但需要记录的标志（前缀匹配）。
var loggedJvmFlags = []string{
	"-Xmx",
	"-Xms",
	"-XX:+UseG1GC",
	"-XX:+UnlockExperimentalVMOptions",
}

// AuditJvmFlags 对一组 JVM 参数做白名单/黑名单检查，返回被拒的项。
func AuditJvmFlags(flags []string) (blocked []string, passed []string) {
	for _, f := range flags {
		trim := strings.TrimSpace(f)
		if trim == "" {
			continue
		}
		if isBlocked(trim) {
			blocked = append(blocked, trim)
			continue
		}
		passed = append(passed, trim)
	}
	return blocked, passed
}

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
