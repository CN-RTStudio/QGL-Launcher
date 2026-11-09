package main

import (
	"strings"
	"time"
)

// collectLatestCrashDump 收集本局最新的崩溃产物摘要。
// 优先结构化的 crash-reports，其次 JVM hs_err；两者都按 notBefore（进程启动时间）
// 过滤陈旧文件。任何候选都不可信，路径、体积、行级全部有界。
func collectLatestCrashDump(gameDir string, notBefore time.Time) (CrashDumpSummary, bool) {
	type candidate struct {
		path, name string
	}
	var minecraftCand, hsCand candidate
	hasMC, hasHS := false, false

	if reportsDir, ok := resolveCrashReportsDir(gameDir); ok {
		if p, n, _, found := pickLatestDumpEntry(reportsDir,
			"crash-", ".txt", notBefore); found {
			minecraftCand, hasMC = candidate{p, n}, true
		}
	}
	if p, n, _, ok := pickLatestDumpEntry(gameDir,
		"hs_err_pid", ".log", notBefore); ok {
		hsCand, hasHS = candidate{p, n}, true
	}

	tryParse := func(c candidate) (CrashDumpSummary, bool) {
		data, good := readDumpBounded(c.path)
		if !good {
			return CrashDumpSummary{}, false
		}
		return parseCrashDump(c.name, data)
	}

	if hasMC {
		if s, ok := tryParse(minecraftCand); ok {
			return s, true
		}
	}
	if hasHS {
		if s, ok := tryParse(hsCand); ok {
			return s, true
		}
	}
	return CrashDumpSummary{}, false
}

// renderCrashDumpSummary 把崩溃产物摘要压成可拼进 crashReason 的紧凑、脱敏文本。
func renderCrashDumpSummary(s CrashDumpSummary) string {
	var b strings.Builder
	if s.FileName != "" {
		b.WriteString("崩溃报告 ")
		b.WriteString(s.FileName)
		b.WriteString("：")
	}
	head := s.Description
	if head == "" {
		head = s.Exception
	}
	if head == "" {
		head = s.InternalError
	}
	if head == "" && s.Problematic != "" {
		head = "Problematic frame " + s.Problematic
	}
	if head == "" {
		head = "检测到崩溃产物但未提取到关键信息"
	}
	b.WriteString(head)

	if s.Exception != "" && s.Exception != s.Description {
		b.WriteString(" | ")
		b.WriteString(s.Exception)
	}
	if s.Problematic != "" && !strings.Contains(head, s.Problematic) {
		b.WriteString(" | frame: ")
		b.WriteString(s.Problematic)
	}
	for _, c := range s.CausedBy {
		b.WriteString(" | Caused by: ")
		b.WriteString(c)
	}
	if len(s.Frames) > 0 {
		n := 3
		if len(s.Frames) < n {
			n = len(s.Frames)
		}
		b.WriteString(" | at ")
		b.WriteString(strings.Join(s.Frames[:n], " <- "))
	}
	if s.Truncated {
		b.WriteString(" (崩溃报告过长已截断)")
	}
	return b.String()
}
