package main

// crashlogenvfilter.go —— 崩溃日志落盘前的环境变量过滤。
//
// 崩溃报告里经常把整个 os.Environ() 塞进去。Windows/启动器场景下 PATH、
// USERPROFILE、APPDATA、JAVA_HOME 这些本身不算秘密，但 Minecraft 启动脚本
// 可能把 access token、session id、自定义代理密码通过环境变量传进去。这里
// 提供一个"崩溃报告可保留的环境变量白名单"纯函数，调用方先过一遍再写盘。

import (
	"strings"
)

// crashLogEnvAllowlist 是崩溃报告允许保留的环境变量名（小写比较）。
var crashLogEnvAllowlist = map[string]bool{
	"PATH":                   true,
	"HOMEDRIVE":              true,
	"HOMEPATH":               true,
	"APPDATA":                true,
	"LOCALAPPDATA":           true,
	"TEMP":                   true,
	"TMP":                    true,
	"USERNAME":               true,
	"USERPROFILE":            true,
	"NUMBER_OF_PROCESSORS":   true,
	"PROCESSOR_ARCHITECTURE": true,
	"OS":                     true,
	"COMPUTERNAME":           true,
	"JAVA_HOME":              true,
	"JAVA_VERSION":           true,
	"LANG":                   true,
	"LC_ALL":                 true,
}

// crashLogEnvBlocklist 是即便不在白名单里也必须硬删的关键词（大小写不敏感）。
// 命中任意一个关键词的环境变量一律打码。
var crashLogEnvBlocklist = []string{
	"token",
	"session",
	"access",
	"secret",
	"password",
	"passwd",
	"api_key",
	"apikey",
	"auth",
	"credential",
	"cookie",
	"authorization",
	"bearer",
	"mojang",
	"microsoft",
	"xbox",
}

// FilterCrashLogEnv 把 os.Environ() 风格的 "K=V" 列表收敛成可落盘的子集。
// 返回的条目仍然是 "K=V" 形态；命中屏蔽关键词的会被替换成 "K=<redacted>"。
func FilterCrashLogEnv(env []string) []string {
	out := make([]string, 0, len(env))
	for _, kv := range env {
		eq := strings.IndexByte(kv, '=')
		if eq <= 0 {
			continue
		}
		key := kv[:eq]
		lk := strings.ToLower(key)
		blocked := false
		for _, bad := range crashLogEnvBlocklist {
			if strings.Contains(lk, bad) {
				blocked = true
				break
			}
		}
		if blocked {
			out = append(out, key+"=<redacted>")
			continue
		}
		if !crashLogEnvAllowlist[strings.ToUpper(key)] {
			continue
		}
		out = append(out, kv)
	}
	return out
}
