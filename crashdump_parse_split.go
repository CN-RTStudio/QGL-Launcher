package main

import (
	"strings"
)

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
