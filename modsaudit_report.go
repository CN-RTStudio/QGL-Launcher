package main

import (
	"sort"
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
