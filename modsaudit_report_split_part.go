package main

import (
	"fmt"
	"strings"
)

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
