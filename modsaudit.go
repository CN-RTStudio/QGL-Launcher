package main

import (
	"path/filepath"
)

const (
	modAuditMaxEntriesDefault = 4000             // 单目录条目数（含一层子目录）上界
	modAuditMaxEntryBytesDef  = int64(256) << 20 // 单文件流式哈希体积上界
	modAuditMaxTotalBytesDef  = int64(4) << 30   // 单目录审计总体积上界
	modAuditMaxSubdirs        = 32               // 一层子目录数量上界
	modAuditRelPathMaxLen     = 512              // 账本内相对路径长度上界
	modAuditBaselineVersion   = 1                // 账本格式版本
)

type ModAuditLimits struct {
	MaxEntries    int
	MaxEntryBytes int64
	MaxTotalBytes int64
}

func defaultModAuditLimits() ModAuditLimits {
	return ModAuditLimits{
		MaxEntries:    modAuditMaxEntriesDefault,
		MaxEntryBytes: modAuditMaxEntryBytesDef,
		MaxTotalBytes: modAuditMaxTotalBytesDef,
	}
}

type ModAuditEntry struct {
	RelPath string `json:"relPath"`
	Name    string `json:"name"`
	Size    int64  `json:"size"`
	UMFS    string `json:"umfs"`
	ModTime string `json:"modTime,omitempty"`
}

const modAuditBaselineFile = "mods-audit-baseline.json"

// modAuditBaselinePath 返回基线账本路径（QGL 目录下，0600 私有文件）。
func (a *App) modAuditBaselinePath() string {
	return filepath.Join(a.GetQGLDir(), modAuditBaselineFile)
}

// auditModsRoots 解析本次要审计的 mods 根（与 moddirscan.resolveModsDirs 同口径：
// 隔离模式额外包含版本目录，全局目录始终包含）。返回绝对路径列表。
