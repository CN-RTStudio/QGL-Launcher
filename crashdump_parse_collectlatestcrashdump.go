package main

import (
	"strings"
	"time"
)

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

// hsFrame 提取 hs_err 里的一帧（去掉前导 # 与帧类型标记 C/J/V/j）。
// 非帧行（纯头部信息）返回空串。
func hsFrame(line string) string {
	trim := strings.TrimSpace(line)
	if !strings.HasPrefix(trim, "#") {
		return ""
	}
	body := strings.TrimSpace(strings.TrimPrefix(trim, "#"))
	if body == "" {
		return ""
	}
	// 帧类型：C=native，J/V/j=Java/VM；后接空格再是符号。
	if len(body) >= 2 && (body[0] == 'C' || body[0] == 'J' ||
		body[0] == 'V' || body[0] == 'j') && body[1] == ' ' {
		return strings.TrimSpace(body[2:])
	}
	return ""
}

// parseCrashDump 根据头部类型分流解析原始内容。
func parseCrashDump(fileName string, data []byte) (CrashDumpSummary, bool) {
	head := ""
	if len(data) > crashDumpProbeBytes {
		head = string(data[:crashDumpProbeBytes])
	} else {
		head = string(data)
	}
	kind := classifyCrashDump(head)
	if kind == "" {
		return CrashDumpSummary{}, false
	}
	lines, truncated := scanCrashLines(data)
	var s CrashDumpSummary
	if kind == "minecraft" {
		s = parseMinecraftCrash(lines)
	} else {
		s = parseHsErrCrash(lines)
	}
	s.FileName = safeCrashName(fileName)
	s.Truncated = truncated
	return s, true
}
