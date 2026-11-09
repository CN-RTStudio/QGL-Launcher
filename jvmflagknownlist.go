package main

import (
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
