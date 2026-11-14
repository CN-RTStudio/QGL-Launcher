package main

import (
	"sort"
)

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
