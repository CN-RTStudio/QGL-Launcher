package main

import "strings"

var jvmPrefixPropThreats = []jvmPropThreat{
	// com.sun.management.jmxremote / .port / .ssl / .authenticate /
	// .access.file / .password.file / .registry.ssl ...
	{"com.sun.management.jmxremote", "jmxremote"},
	// java.rmi.server.codebase 等远程类加载相关项。
	{"java.rmi.server.codebase", "rmi-codebase"},
}

// parseSystemPropertyArg 解析形如 "-Dname=value" 的参数。
// 入参 arg 必须已是 strings.ToLower(strings.TrimSpace(...))。
// 返回 isProp=true 时 name 为小写属性名、value 为首个 '=' 之后的原始（小写）值。
// "-D" 后面没有名字（裸 "-d" / "-d32" 这类以数字开头的历史开关）不算系统属性。
func parseSystemPropertyArg(lower string) (name, value string, isProp bool) {
	if !strings.HasPrefix(lower, "-d") || len(lower) <= 2 {
		return "", "", false
	}
	body := lower[2:]
	if body == "" {
		return "", "", false
	}
	// 属性名首字符必须是字母，排除 -d32 / -d64 / -dsa 这类历史 JVM 开关被误判。
	first := body[0]
	if !(first >= 'a' && first <= 'z') {
		return "", "", false
	}
	if eq := strings.IndexByte(body, '='); eq >= 0 {
		return strings.TrimSpace(body[:eq]), body[eq+1:], true
	}
	return strings.TrimSpace(body), "", true
}
