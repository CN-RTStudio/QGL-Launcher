package main

import (
	"strings"
)

// maxLaunchSnapshots 磁盘上最多保留的快照份数。
const maxLaunchSnapshots = 10

// maxSnapshotFieldLen 单个字段长度上限（Java 路径 / 版本 ID 都可能很长）。
const maxSnapshotFieldLen = 1024

// LaunchSnapshot 是一次启动的参数快照（可落盘，字段已收口）。
type LaunchSnapshot struct {
	VersionID        string `json:"versionId"`
	JavaPath         string `json:"javaPath"`
	JavaVersion      string `json:"javaVersion,omitempty"`
	MaxMemMB         int    `json:"maxMemMB,omitempty"`
	AuthType         string `json:"authType,omitempty"`
	ModsCount        int    `json:"modsCount,omitempty"`
	OnlineMode       bool   `json:"onlineMode"`
	PreflightBlocked bool   `json:"preflightBlocked,omitempty"`
	PreflightIssues  int    `json:"preflightIssues,omitempty"`
	CreatedAt        string `json:"createdAt"` // RFC3339
}

// sanitizeSnapshotField 单字段收口：去控制字符并截断，空串归一为 ""。
func sanitizeSnapshotField(s string, maxLen int) string {
	s = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return -1
		}
		return r
	}, s)
	s = strings.TrimSpace(s)
	if len(s) > maxLen {
		s = s[:maxLen]
	}
	return s
}
