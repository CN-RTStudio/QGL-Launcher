package main

import (
	"fmt"
	"strings"
)

func auditMainClass(mainClass string) []LaunchFinding {
	var out []LaunchFinding
	if strings.TrimSpace(mainClass) == "" {
		return out // -jar 模式下为空，合法。
	}
	if len(mainClass) > maxMainClassLen {
		return append(out, LaunchFinding{"main-long", launchSeverityCritical, "mainClass", "主类名过长"})
	}
	if containsControlByte(mainClass) || strings.ContainsAny(mainClass, " \t") {
		return append(out, LaunchFinding{"main-control", launchSeverityCritical, "mainClass", "主类名含空白或控制字符"})
	}
	if strings.HasPrefix(mainClass, "-") || strings.HasPrefix(mainClass, "@") {
		return append(out, LaunchFinding{"main-option-like", launchSeverityCritical, "mainClass", "主类名形似 JVM 选项或 argfile"})
	}
	cls := mainClass
	if idx := strings.Index(mainClass, "/"); idx >= 0 {
		cls = mainClass[idx+1:] // 丢掉可选的 module/ 前缀，仅校验类名部分
	}
	if cls == "" {
		return append(out, LaunchFinding{"main-empty-class", launchSeverityCritical, "mainClass", "缺少类名部分"})
	}
	for _, seg := range strings.Split(cls, ".") {
		if seg == "" {
			return append(out, LaunchFinding{"main-empty-segment", launchSeverityCritical, "mainClass", "主类名含空段"})
		}
		if !isJavaIdentSegment(seg) {
			return append(out, LaunchFinding{"main-bad-char", launchSeverityCritical, "mainClass", "主类名含非法字符"})
		}
	}
	return out
}

func isJavaIdentSegment(seg string) bool {
	for i := 0; i < len(seg); i++ {
		c := seg[i]
		if c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_' || c == '$' {
			continue
		}
		return false
	}
	return true
}
func auditProgramArgs(args []string) []LaunchFinding {
	var out []LaunchFinding
	if len(args) > maxLaunchArgs {
		return append(out, LaunchFinding{"args-too-many", launchSeverityCritical, "programArgs", "程序参数数量过多"})
	}
	for i, arg := range args {
		field := fmt.Sprintf("programArgs[%d]", i)
		if len(arg) > maxLaunchArgBytes {
			out = append(out, LaunchFinding{"arg-long", launchSeverityCritical, field, "单个程序参数过长"})
			continue
		}
		if containsControlByte(arg) {
			out = append(out, LaunchFinding{"arg-control", launchSeverityCritical, field, "程序参数含控制字符"})
		}
	}
	return out
}
