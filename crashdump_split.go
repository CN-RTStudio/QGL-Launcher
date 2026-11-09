package main

//
//
//

import (
	"bytes"
	"strings"
)

func cleanCrashLine(line string) string {
	return boundCrashContextLine(strings.TrimRight(sanitizeLogLine(line), "\r"))
}

// scanCrashLines 把原始字节按有界、有单行上限的方式切成干净行。
// 返回行切片与是否发生截断（超长行 / 行数超限）。
func scanCrashLines(data []byte) ([]string, bool) {
	truncated := false
	count := 0
	var lines []string
	_, lineTrunc, _ := streamBoundedLines(bytes.NewReader(data), crashDumpLineMaxBytes, func(line string) {
		count++
		if count > crashDumpMaxLines {
			truncated = true
			return
		}
		lines = append(lines, cleanCrashLine(line))
	})
	if lineTrunc > 0 {
		truncated = true
	}
	return lines, truncated
}

// parseMinecraftCrash 解析 crash-reports/crash-*.txt 的结构化内容。
func parseMinecraftCrash(lines []string) CrashDumpSummary {
	s := CrashDumpSummary{Kind: "minecraft"}
	afterDescription := false
	for _, line := range lines {
		trim := strings.TrimSpace(line)

		// System Details / 末段走查之后是环境与硬件噪声，停止收集。
		if strings.HasPrefix(trim, "-- System Details --") ||
			strings.HasPrefix(trim, "A detailed walkthrough") {
			break
		}

		if strings.HasPrefix(trim, "Description:") {
			desc := strings.TrimSpace(strings.TrimPrefix(trim, "Description:"))
			if desc != "" && s.Description == "" {
				s.Description = desc
			}
			afterDescription = true
			continue
		}
		// Description 的续行（缩进、无键名），最多并入两行。
		if afterDescription && s.Description != "" && trim != "" &&
			!strings.Contains(trim, ":") && strings.HasPrefix(line, " ") {
			if len(s.Description) < 512 {
				s.Description = strings.TrimSpace(s.Description + " " + trim)
			}
			continue
		}
		if trim == "" {
			afterDescription = false
		}

		if strings.HasPrefix(trim, "Caused by:") {
			s.CausedBy = appendUnique(s.CausedBy,
				strings.TrimSpace(strings.TrimPrefix(trim, "Caused by:")), crashDumpMaxCaused)
			continue
		}

		if strings.HasPrefix(trim, "at ") && strings.Contains(trim, "(") {
			if len(s.Frames) < crashDumpMaxFrames {
				s.Frames = append(s.Frames, trim)
			}
			continue
		}

		// 顶层异常通常出现在 Description 之后、栈帧之前。
		if s.Exception == "" && looksLikeJavaException(trim) {
			s.Exception = trim
		}
	}
	return s
}

// parseHsErrCrash 解析 hs_err_pid*.log 的关键信息。
