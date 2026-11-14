package main

import (
	"os"
	"strings"
)

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
