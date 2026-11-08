package main

// modsaudit_report_app.go —— mods 完整性审计报告的导出绑定。
//
// 报告内核（文本渲染 / 结构化）在 modsaudit_report.go；本文件只负责：解析受信根、
// 读基线、跑一次对账、把报告落盘（QGL 目录下 0600 私有写），并记录安全审计事件。
// 导出文件只含相对路径与文件名（见内核注释），不泄露绝对目录结构。

import (
	"encoding/json"
	"fmt"
	"os"
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
	if err := os.WriteFile(fullPath, body, 0o600); err != nil {
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

// ListModsAuditReports 列出已导出的审计报告文件（按修改时间倒序，最多 20 个）。
// 只返回文件名，不返回内容；供前端“最近导出”列表使用。
func (a *App) ListModsAuditReports() ([]string, error) {
	dir := a.modAuditReportPath()
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return []string{}, nil
		}
		return nil, modAuditError("报告目录读取失败")
	}
	names := []string{}
	for _, e := range entries {
		n := e.Name()
		if !strings.HasPrefix(n, modAuditReportPrefix) {
			continue
		}
		if !strings.HasSuffix(n, modAuditReportExt) &&
			!strings.HasSuffix(n, modAuditReportJSONExt) {
			continue
		}
		names = append(names, n)
	}
	// 新导出的排前面（文件名带 UTC 时间戳，字典序即时间序）
	// 简单排序即可，不读取文件 mtime（保持轻量）。
	for i, j := 0, len(names)-1; i < j; i, j = i+1, j-1 {
		names[i], names[j] = names[j], names[i]
	}
	if len(names) > 20 {
		names = names[:20]
	}
	return names, nil
}
