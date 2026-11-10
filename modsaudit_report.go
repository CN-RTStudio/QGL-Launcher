package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

const (
	modAuditReportMaxRows = 200     // 每类差异在报告中最多列出的行数
	modAuditReportMaxLen  = 8 << 20 // 单份报告文本最大长度（8MB）
	modAuditDetailMaxLen  = 200     // 单条 detail 文本最大长度
)

type ModAuditReportFile struct {
	Version       int             `json:"version"`              // 报告格式版本
	GeneratedAt   string          `json:"generatedAt"`          // 生成时间（UTC RFC3339）
	BaselineAt    string          `json:"baselineAt,omitempty"` // 基线账本时间（可为空）
	BaselineDirs  int             `json:"baselineDirs"`         // 基线覆盖目录数
	Total         int             `json:"total"`                // 当前审计文件总数
	Consistent    int             `json:"consistent"`           // 与基线一致数
	Skipped       int             `json:"skipped"`              // 跳过（特殊条目/超限）数
	LimitHit      bool            `json:"limitHit"`             // 是否触及资源上限
	HasRisks      bool            `json:"hasRisks"`             // 是否存在任何风险
	Added         []ModAuditDelta `json:"added"`                // 新增（有限）
	Missing       []ModAuditDelta `json:"missing"`              // 缺失（有限）
	Tampered      []ModAuditDelta `json:"tampered"`             // 篡改（有限）
	AddedCount    int             `json:"addedCount"`           // 新增总数（含未列出的）
	MissingCount  int             `json:"missingCount"`         // 缺失总数
	TamperedCount int             `json:"tamperedCount"`        // 篡改总数
}

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

func clipReportDeltas(deltas []ModAuditDelta, limit int) ([]ModAuditDelta, int) {
	if len(deltas) <= limit {
		return deltas, 0
	}
	return deltas[:limit], len(deltas) - limit
}

// modAuditDeltaSortKey 排序键：目录 + 相对路径，保证报告输出稳定、可对比。
func modAuditDeltaSortKey(d ModAuditDelta) string {
	return d.Dir + "/" + d.RelPath
}

// sortReportDeltas 按目录 + 相对路径排序差异列表（原地）。
func sortReportDeltas(deltas []ModAuditDelta) {
	sort.SliceStable(deltas, func(i, j int) bool {
		return modAuditDeltaSortKey(deltas[i]) < modAuditDeltaSortKey(deltas[j])
	})
}

// clipDetail 截断差异 detail 文本到上界，防止脏文件名/脏描述撑爆报告。
func clipDetail(s string) string {
	if len(s) <= modAuditDetailMaxLen {
		return s
	}
	return s[:modAuditDetailMaxLen-3] + "..."
}

func buildModAuditReportFile(r ModAuditReport, baseline *ModAuditSnapshot, now string) ModAuditReportFile {
	sortReportDeltas(r.Added)
	sortReportDeltas(r.Missing)
	sortReportDeltas(r.Tampered)
	added, addedRest := clipReportDeltas(r.Added, modAuditReportMaxRows)
	missing, missingRest := clipReportDeltas(r.Missing, modAuditReportMaxRows)
	tampered, tamperedRest := clipReportDeltas(r.Tampered, modAuditReportMaxRows)
	for i := range added {
		added[i].Detail = clipDetail(added[i].Detail)
	}
	for i := range missing {
		missing[i].Detail = clipDetail(missing[i].Detail)
	}
	for i := range tampered {
		tampered[i].Detail = clipDetail(tampered[i].Detail)
	}
	out := ModAuditReportFile{
		Version:       modAuditBaselineVersion,
		GeneratedAt:   now,
		Total:         r.Total,
		Consistent:    r.Consistent,
		Skipped:       r.Skipped,
		LimitHit:      r.LimitHit,
		HasRisks:      r.HasRisks,
		Added:         added,
		Missing:       missing,
		Tampered:      tampered,
		AddedCount:    len(r.Added),
		MissingCount:  len(r.Missing),
		TamperedCount: len(r.Tampered),
	}
	if baseline != nil {
		out.BaselineAt = baseline.CreatedAt
		out.BaselineDirs = len(baseline.Dirs)
	}
	_ = addedRest
	_ = missingRest
	_ = tamperedRest
	return out
}

func modAuditReportText(r ModAuditReport, baseline *ModAuditSnapshot, now string) string {
	f := buildModAuditReportFile(r, baseline, now)
	var b strings.Builder
	b.WriteString("OpenQGL mods 目录完整性审计报告\n")
	b.WriteString("生成时间: " + f.GeneratedAt + "\n")
	if f.BaselineAt != "" {
		b.WriteString("基线账本: " + f.BaselineAt + "（" + fmt.Sprint(f.BaselineDirs) + " 个目录）\n")
	} else {
		b.WriteString("基线账本: 无（首次审计，全部文件视为新增）\n")
	}
	b.WriteString(fmt.Sprintf("当前文件: %d 个，与基线一致 %d 个，跳过 %d 个",
		f.Total, f.Consistent, f.Skipped))
	if f.LimitHit {
		b.WriteString("，触及资源上限")
	}
	b.WriteString("\n")

	section := func(title string, items []ModAuditDelta, total int) {
		if total == 0 {
			return
		}
		b.WriteString("\n" + title + ": " + fmt.Sprint(total) + " 项\n")
		rest := total - len(items)
		for _, d := range items {
			line := "  [" + d.Dir + "] " + d.Name
			if d.RelPath != d.Name {
				line += "（" + d.RelPath + "）"
			}
			if d.Detail != "" {
				line += " — " + d.Detail
			}
			if len(line) > 400 {
				line = line[:397] + "..."
			}
			b.WriteString(line + "\n")
		}
		if rest > 0 {
			b.WriteString("  … 其余 " + fmt.Sprint(rest) + " 项未列出\n")
		}
	}
	section("篡改", f.Tampered, f.TamperedCount)
	section("新增", f.Added, f.AddedCount)
	section("缺失", f.Missing, f.MissingCount)

	if !f.HasRisks {
		b.WriteString("\n结论: 未发现风险，mods 目录与基线一致。\n")
	} else {
		b.WriteString("\n结论: 存在风险，请按上表逐项核对后再启动游戏。\n")
	}
	out := b.String()
	if len(out) > modAuditReportMaxLen {
		return out[:modAuditReportMaxLen-3] + "..."
	}
	return out
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
