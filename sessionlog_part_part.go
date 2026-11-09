package main

import (
	"path/filepath"
	"strings"
	"time"
)

func redactLikelyToken(s string) string {
	// JWT：header.payload.signature。header 恒为 eyJ 开头，任一位置出现
	// 且带两个点分隔即整体替换（防半截 token 落盘）。
	if strings.Count(s, ".") >= 2 && strings.Contains(s, "eyJ") {
		return "[REDACTED-JWT]"
	}
	// 显式键值令牌：token= / key= / secret= / password= 后面的长串。
	idx := strings.Index(s, "=")
	if idx > 0 && idx < len(s)-16 {
		key := strings.ToLower(strings.TrimSpace(s[:idx]))
		switch {
		case strings.Contains(key, "token"),
			strings.Contains(key, "secret"),
			strings.Contains(key, "password"),
			strings.Contains(key, "apikey"),
			strings.Contains(key, "auth"):
			rest := s[idx+1:]
			if len(rest) >= 16 {
				return s[:idx+1] + "[REDACTED]"
			}
		}
	}
	return s
}

// sessionLogFileNameFor 生成稳定的会话日志文件名：sessionlog-<version>-<stamp>.json。
// version 必须已通过 sanitizePathComponent（调用方负责），stamp 取
// 20060102T150405 形式，保证同一目录下唯一且可按字典序排序（时间序）。
func sessionLogFileNameFor(versionID string, startedAt time.Time) string {
	stamp := startedAt.Format("20060102T150405")
	return "sessionlog-" + versionID + "-" + stamp + ".json"
}

// sessionLogFilePathFor 返回会话日志完整路径（QGL 目录下）。
func sessionLogFilePathFor(qglDir, versionID string, startedAt time.Time) string {
	return filepath.Join(qglDir, sessionLogFileNameFor(versionID, startedAt))
}
