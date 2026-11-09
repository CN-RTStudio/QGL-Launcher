package main

import (
	"path/filepath"
	"strings"
)

const modAuditBaselineFile = "mods-audit-baseline.json"

// modAuditBaselinePath 返回基线账本路径（QGL 目录下，0600 私有文件）。
func (a *App) modAuditBaselinePath() string {
	return filepath.Join(a.GetQGLDir(), modAuditBaselineFile)
}

// auditModsRoots 解析本次要审计的 mods 根（与 moddirscan.resolveModsDirs 同口径：
// 隔离模式额外包含版本目录，全局目录始终包含）。返回绝对路径列表。
func (a *App) auditModsRoots(versionID string) []string {
	return a.resolveModsDirs(versionID)
}

// RebuildModsAuditBaseline 重新生成 mods 目录完整性基线账本，覆盖旧账本。
// 返回新账本的统计（目录数 / 文件总数 / 跳过数 / 是否触及上限）。生成账本本身
// 不判风险——它只是“此后的对账基准”。
func (a *App) RebuildModsAuditBaseline(versionID string) (*ModAuditBaselineInfo, error) {
	if versionID != "" && (strings.Contains(versionID, "..") ||
		strings.Contains(versionID, "/") || strings.Contains(versionID, "\\")) {
		return nil, modAuditError("版本ID包含非法字符")
	}
	roots := a.auditModsRoots(versionID)
	snap, skipped, limitHit, err := buildModAuditSnapshot(roots, defaultModAuditLimits())
	if err != nil {
		recordSecurityEvent(auditCategoryJarScan, auditSeverityWarn, auditActionDetected,
			"mods-audit", "mods 审计基线生成失败")
		return nil, modAuditError("mods 审计基线生成失败")
	}
	if err := saveModAuditSnapshot(a.modAuditBaselinePath(), snap); err != nil {
		recordSecurityEvent(auditCategoryJarScan, auditSeverityWarn, auditActionDetected,
			"mods-audit", "mods 审计基线落盘失败")
		return nil, modAuditError("mods 审计基线落盘失败")
	}
	info := &ModAuditBaselineInfo{
		Dirs:       len(snap.Dirs),
		TotalFiles: 0,
		Skipped:    skipped,
		LimitHit:   limitHit,
	}
	for _, d := range snap.Dirs {
		info.TotalFiles += len(d.Entries)
	}
	recordSecurityEvent(auditCategoryJarScan, auditSeverityInfo, auditActionDetected,
		"mods-audit", modAuditBaselineInfoText(info))
	return info, nil
}
