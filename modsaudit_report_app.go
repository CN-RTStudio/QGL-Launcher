package main

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"
	"time"
)

const (
	modAuditReportDir     = "reports"
	modAuditReportPrefix  = "mods-audit-report-"
	modAuditReportExt     = ".txt"
	modAuditReportJSONExt = ".json"
)

// modAuditReportPath 返回报告导出目录（QGL 目录 / reports）。
func (a *App) modAuditReportPath() string {
	return filepath.Join(a.GetQGLDir(), modAuditReportDir)
}

// ExportModsAuditReport 跑一次 mods 完整性审计并把结果落盘。
// format: "text"（默认，人读）或 "json"（结构化）。返回导出的文件名与绝对路径。
// 文件写入走 0600 原子私有写（safeio 同款语义），文件名带时间戳避免互相覆盖。
func (a *App) ExportModsAuditReport(versionID, format string) (string, string, error) {
	if versionID != "" && (strings.Contains(versionID, "..") ||
		strings.Contains(versionID, "/") || strings.Contains(versionID, "\\")) {
		return "", "", modAuditError("版本ID包含非法字符")
	}
	baseline, err := loadModAuditSnapshot(a.modAuditBaselinePath())
	if err != nil {
		return "", "", modAuditError("mods 审计基线读取失败")
	}
	roots := a.auditModsRoots(versionID)
	current, skipped, limitHit, err := buildModAuditSnapshot(roots, defaultModAuditLimits())
	if err != nil {
		return "", "", modAuditError("mods 目录扫描失败")
	}
	report := auditModsAgainstBaseline(current, baseline)
	report.Skipped = skipped
	report.LimitHit = limitHit

	now := time.Now().UTC().Format(time.RFC3339)
	var body []byte
	var ext string
	if strings.EqualFold(strings.TrimSpace(format), "json") {
		f := buildModAuditReportFile(report, baseline, now)
		body, err = json.MarshalIndent(f, "", "  ")
		if err != nil {
			return "", "", modAuditError("报告序列化失败")
		}
		ext = modAuditReportJSONExt
	} else {
		body = []byte(modAuditReportText(report, baseline, now))
		ext = modAuditReportExt
	}

	dir := a.modAuditReportPath()
	if err := ensurePrivateDir(dir); err != nil {
		return "", "", modAuditError("报告目录创建失败")
	}
	fileName := modAuditReportPrefix +
		strings.ReplaceAll(now, ":", "-") + ext
	fullPath := filepath.Join(dir, fileName)
	if err := secureWritePrivateFile(fullPath, body); err != nil {
		recordSecurityEvent(auditCategoryJarScan, auditSeverityWarn, auditActionDetected,
			"mods-audit", "mods 审计报告导出失败")
		return "", "", modAuditError("mods 审计报告导出失败")
	}

	severity := auditSeverityInfo
	if report.HasRisks {
		severity = auditSeverityWarn
		if len(report.Tampered) > 0 {
			severity = auditSeverityCritical
		}
	}
	recordSecurityEvent(auditCategoryJarScan, severity, auditActionDetected,
		"mods-audit", fmt.Sprintf("mods 审计报告已导出: %s", fileName))
	return fileName, fullPath, nil
}
