package main

import (
	"bytes"
	"path/filepath"
	"strings"
)

const (
	// crashDumpMaxBytes 单个崩溃产物的读取上限（本地生成文本，阈值取宽，只拦磁盘炸弹）。
	crashDumpMaxBytes = 4 << 20
	// crashDumpMaxLines 单个产物参与解析的最大行数。
	crashDumpMaxLines = 400
	// crashDumpLineMaxBytes 单行字节上限，复用日志流式读取的单行策略。
	crashDumpLineMaxBytes = 4096
	// crashDumpMaxFrames 保留的栈帧上限。
	crashDumpMaxFrames = 40
	// crashDumpMaxCaused 保留的 “Caused by” 链上限。
	crashDumpMaxCaused = 8
	// crashDumpProbeBytes 判定产物类型时读取的头部探测长度。
	crashDumpProbeBytes = 4096
)

type CrashDumpSummary struct {
	Kind          string   // "minecraft"：crash-reports；"hs_err"：JVM 致命错误
	FileName      string   // 仅基名（已做词法收敛），不含目录
	Description   string   // Minecraft 报告的 Description: 段
	Exception     string   // 顶层异常 / hs_err EXCEPTION_* 信号
	CausedBy      []string // Caused by 链（去重、有上限）
	Frames        []string // 关键栈帧（有上限）
	Problematic   string   // hs_err: Problematic frame
	InternalError string   // hs_err: Internal Error (...)
	Heads         []string // 少量关键头部行（信号/内部事件）
	Truncated     bool     // 体积/行数/单行超限导致的截断
}

func classifyCrashDump(head string) string {
	if strings.Contains(head, "Minecraft Crash Report") {
		return "minecraft"
	}
	if strings.Contains(head, "A fatal error has been detected by the Java Runtime Environment") ||
		strings.Contains(head, "EXCEPTION_ACCESS_VIOLATION") ||
		strings.Contains(head, "SIGSEGV") {
		return "hs_err"
	}
	return ""
}

func safeCrashName(name string) string {
	name = filepath.Base(name)
	if name == "." || name == string(filepath.Separator) {
		return ""
	}
	return SanitizeFilename(name)
}

// looksLikeJavaException 粗判一行是否是顶层 Java 异常：
// 形如 "java.lang.IllegalStateException: ..." 或含全限定异常类型且带 Exception/Error。
func looksLikeJavaException(line string) bool {
	trim := strings.TrimSpace(line)
	if trim == "" || strings.HasPrefix(trim, "--") || strings.HasPrefix(trim, "at ") {
		return false
	}
	if !strings.Contains(trim, ".") {
		return false
	}
	return strings.Contains(trim, "Exception") || strings.Contains(trim, "Error") ||
		strings.Contains(trim, "Throwable")
}

// appendUnique 往切片追加不重复且有数量上限的字符串。
func appendUnique(list []string, s string, max int) []string {
	s = strings.TrimSpace(s)
	if s == "" {
		return list
	}
	for _, existing := range list {
		if existing == s {
			return list
		}
	}
	if len(list) >= max {
		return list
	}
	return append(list, s)
}

func cleanCrashLine(line string) string {
	return boundCrashContextLine(strings.TrimRight(sanitizeLogLine(line), "\r"))
}
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
