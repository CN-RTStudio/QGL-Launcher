package main

import (
	"strings"
)

func normSnapshotPath(p string) string {
	p = strings.TrimSpace(p)
	p = strings.TrimRight(p, "/\\")
	return strings.ToLower(p)
}

// configSnapshotEqual 判断两份快照完全一致（落盘前判断是否真的变了）。
func configSnapshotEqual(a, b configSnapshot) bool {
	return normSnapshotPath(a.JavaPath) == normSnapshotPath(b.JavaPath) &&
		a.MaxMemMB == b.MaxMemMB &&
		normSnapshotPath(a.GameDir) == normSnapshotPath(b.GameDir) &&
		a.VersionID == b.VersionID &&
		a.AuthTypeLabel == b.AuthTypeLabel
}

// configSnapshotDiffsText 把变化字段整理成一行审计文本。
func configSnapshotDiffsText(fields []string) string {
	if len(fields) == 0 {
		return ""
	}
	return "关键配置被外部篡改: " + strings.Join(fields, "、")
}

// configSnapshotSanitize 对快照字段做收口（控制字符剥离 + 限长），防把畸形
// 值写进基线文件本身。
func configSnapshotSanitize(s configSnapshot) configSnapshot {
	return configSnapshot{
		JavaPath:      sanitizeLedgerField(s.JavaPath, 1024),
		MaxMemMB:      s.MaxMemMB,
		GameDir:       sanitizeLedgerField(s.GameDir, 1024),
		VersionID:     sanitizeLedgerField(s.VersionID, 128),
		AuthTypeLabel: sanitizeLedgerField(s.AuthTypeLabel, 32),
	}
}
