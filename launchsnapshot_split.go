package main

import (
	"sort"
	"time"
)

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
