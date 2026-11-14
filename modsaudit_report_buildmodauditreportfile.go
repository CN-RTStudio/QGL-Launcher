package main

import (
	"fmt"
	"os"
	"strings"
)

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
