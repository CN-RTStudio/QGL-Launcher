package main

// launchsnapshot.go —— 启动参数快照（launch snapshot）纯函数内核。
//
// 背景：sessionjournal 记录了“哪次启动、何时结束、结局如何”，但没有记录
// “用什么启动的”——Java 路径 / 内存参数 / auth 类型 / mods 数量。事后审计
// 只能看到结果，看不到配置，出问题难以复现。本模块在每次启动前把关键参数
// 脱敏后落一份快照（launch-snapshot.json），与 session journal 互补。
//
// 设计：
//   - 纯函数：给定启动参数，产出可落盘的快照结构；任何字段都做长度 / 控制
//     字符收口，绝不把用户输入原样写盘（Java 路径、版本 ID 可能带不可信字符）；
//   - 快照只存最近 N 份（环形，防无限膨胀）；
//   - 不含任何凭证：OAuth token、refresh token 一律不进入快照，只记 auth 类型。

import (
	"sort"
	"strings"
	"time"
)

// maxLaunchSnapshots 磁盘上最多保留的快照份数。
const maxLaunchSnapshots = 10

// maxSnapshotFieldLen 单个字段长度上限（Java 路径 / 版本 ID 都可能很长）。
const maxSnapshotFieldLen = 1024

// LaunchSnapshot 是一次启动的参数快照（可落盘，字段已收口）。
type LaunchSnapshot struct {
	VersionID      string    `json:"versionId"`
	JavaPath       string    `json:"javaPath"`
	JavaVersion    string    `json:"javaVersion,omitempty"`
	MaxMemMB       int       `json:"maxMemMB,omitempty"`
	AuthType       string    `json:"authType,omitempty"`
	ModsCount      int       `json:"modsCount,omitempty"`
	OnlineMode     bool      `json:"onlineMode"`
	PreflightBlocked bool    `json:"preflightBlocked,omitempty"`
	PreflightIssues int      `json:"preflightIssues,omitempty"`
	CreatedAt      string    `json:"createdAt"` // RFC3339
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

// buildLaunchSnapshot 由启动参数构造快照。不信任任何外部输入：字段逐项收口；
// 快照里只放审计所需信息，凭证类字段（token 等）根本不在参数列表中。
func buildLaunchSnapshot(versionID, javaPath, javaVersion, authType string,
	maxMemMB, modsCount int, onlineMode bool, preflightBlocked bool, preflightIssues int) LaunchSnapshot {
	return LaunchSnapshot{
		VersionID:        sanitizeSnapshotField(versionID, maxSnapshotFieldLen),
		JavaPath:         sanitizeSnapshotField(javaPath, maxSnapshotFieldLen),
		JavaVersion:      sanitizeSnapshotField(javaVersion, 128),
		MaxMemMB:         maxMemMB,
		AuthType:         sanitizeSnapshotField(authType, 64),
		ModsCount:        modsCount,
		OnlineMode:       onlineMode,
		PreflightBlocked: preflightBlocked,
		PreflightIssues:  preflightIssues,
		CreatedAt:        time.Now().Format(time.RFC3339),
	}
}

// decideSnapshotRetention 纯函数：新增一条快照并淘汰最旧，返回应写盘的列表。
// 入参不被修改（“纯函数不改入参”与现有模块口径一致）。上限 <= 0 时用默认值。
func decideSnapshotRetention(snapshots []LaunchSnapshot, next LaunchSnapshot, capN int) []LaunchSnapshot {
	if capN <= 0 {
		capN = maxLaunchSnapshots
	}
	out := append([]LaunchSnapshot(nil), snapshots...)
	out = append(out, next)
	if len(out) > capN {
		out = out[len(out)-capN:]
	}
	return out
}

// sortSnapshotsNewestFirst 按 CreatedAt 倒序排序（RFC3339 字典序即时间序）。
func sortSnapshotsNewestFirst(snaps []LaunchSnapshot) {
	sort.Slice(snaps, func(i, j int) bool {
		return snaps[i].CreatedAt > snaps[j].CreatedAt
	})
}
