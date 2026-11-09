package main

import (
	"fmt"
	"os"
	"strconv"
	"strings"
)

// AuditModsIntegrity 把当前 mods 目录与基线账本对账，返回差异报告。
// 无基线时全量视为“新增”（对首次审计友好：不会把既有文件误报为篡改）。
// 发现篡改 / 缺失 / 新增都会写安全审计事件，但绝不自动删除文件。
func (a *App) AuditModsIntegrity(versionID string) (*ModAuditReport, error) {
	if versionID != "" && (strings.Contains(versionID, "..") ||
		strings.Contains(versionID, "/") || strings.Contains(versionID, "\\")) {
		return nil, modAuditError("版本ID包含非法字符")
	}
	baseline, err := loadModAuditSnapshot(a.modAuditBaselinePath())
	if err != nil {
		recordSecurityEvent(auditCategoryJarScan, auditSeverityWarn, auditActionDetected,
			"mods-audit", "mods 审计基线读取失败")
		return nil, modAuditError("mods 审计基线读取失败")
	}
	roots := a.auditModsRoots(versionID)
	current, skipped, limitHit, err := buildModAuditSnapshot(roots, defaultModAuditLimits())
	if err != nil {
		return nil, modAuditError("mods 目录扫描失败")
	}
	report := auditModsAgainstBaseline(current, baseline)
	report.Skipped = skipped
	report.LimitHit = limitHit

	severity := auditSeverityInfo
	if report.HasRisks {
		severity = auditSeverityWarn
		if len(report.Tampered) > 0 {
			severity = auditSeverityCritical
		}
	}
	recordSecurityEvent(auditCategoryJarScan, severity, auditActionDetected,
		"mods-audit", modAuditSummaryText(report))
	return &report, nil
}

// ClearModsAuditBaseline 删除基线账本（用户想完全重置对账基准时使用）。
func (a *App) ClearModsAuditBaseline() error {
	path := a.modAuditBaselinePath()
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		recordSecurityEvent(auditCategoryJarScan, auditSeverityWarn, auditActionDetected,
			"mods-audit", "mods 审计基线删除失败")
		return modAuditError("mods 审计基线删除失败")
	}
	recordSecurityEvent(auditCategoryJarScan, auditSeverityInfo, auditActionDetected,
		"mods-audit", "mods 审计基线已清除")
	return nil
}

// ModAuditBaselineInfo 是新基线账本的统计信息。
type ModAuditBaselineInfo struct {
	Dirs       int  `json:"dirs"`
	TotalFiles int  `json:"totalFiles"`
	Skipped    int  `json:"skipped"`
	LimitHit   bool `json:"limitHit"`
}

func modAuditBaselineInfoText(i *ModAuditBaselineInfo) string {
	return "mods 审计基线已建立: " +
		strconv.Itoa(i.Dirs) + " 个目录 / " +
		strconv.Itoa(i.TotalFiles) + " 个文件 / " +
		strconv.Itoa(i.Skipped) + " 个跳过"
}

// modAuditError 生成带统一前缀的错误文案，便于前端识别。
func modAuditError(msg string) error {
	return fmt.Errorf("mods 完整性审计: %s", msg)
}
