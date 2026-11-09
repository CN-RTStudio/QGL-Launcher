package main

// modsaudit_report.go —— mods 完整性审计报告的文本渲染内核。
//
// 背景：
//   modsaudit.go 已能产出结构化 ModAuditReport，但启动器里没有“把报告落盘给人看”
//   的通道：审计事件只进日志，用户想核对“这次多了哪几个 mod、哪个被改过”没有
//   便捷途径。本文件把报告渲染成有界、可读、可留档的文本与 JSON 两种形式，供
//   Wails 绑定导出到 QGL 目录（0600 私有写）。
//
// 设计要点：
//   - 渲染纯函数化、不依赖 App / 平台，可独立单测；所有字符串都有长度上界，防止
//     恶意文件名把导出文件撑爆（本地 DoS）；
//   - 差异条目按目录排序、每类最多列 MOD_AUDIT_REPORT_MAX_ROWS 行，超出折叠成
//     “… 其余 N 项”，保证大目录（上限 4000 条目）不会产出百万行报告；
//   - 文本版面向人读：先给汇总，再按篡改 / 新增 / 缺失分节列明细；
//   - JSON 版面向机器读：汇总 + 有限明细 + 基线时间 / 版本号，字段全部类型收口；
//   - 报告里只含相对路径与文件名，不含绝对路径，避免把本机目录结构泄露到导出
//     文件（导出文件可能被用户分享给他人排查）。

import (
	"fmt"
	"sort"
	"strings"
)

// mods 审计报告渲染的资源上界。
const (
	modAuditReportMaxRows = 200     // 每类差异在报告中最多列出的行数
	modAuditReportMaxLen  = 8 << 20 // 单份报告文本最大长度（8MB）
	modAuditDetailMaxLen  = 200     // 单条 detail 文本最大长度
)

// ModAuditReportFile 是导出报告的结构化内容：汇总 + 有限明细。
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

// clipReportDeltas 把差异列表截断到报告行数上界，返回截断后的列表与剩余计数。
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

// buildModAuditReportFile 把结构化报告转成导出内容。baseline 可为 nil（无基线）。
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

// modAuditReportText 渲染人读文本版报告。返回值已受 modAuditReportMaxLen 上界约束。
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
