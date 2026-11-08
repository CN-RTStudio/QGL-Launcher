package main

// crashdump.go —— 游戏崩溃产物（crash-reports/*.txt 与 hs_err_pid*.log）的有界解析器。
//
// 威胁模型与动机：
//   现有崩溃检测只扫描 stdout/stderr 里的关键字。但 JVM 原生崩溃
//   （EXCEPTION_ACCESS_VIOLATION / SIGSEGV 等）时，控制台往往只有一句
//   “A fatal error has been detected by the Java Runtime Environment”，真正的
//   异常线程、Problematic frame、C/Java 栈和内部错误码都落在 hs_err_pid*.log；
//   而 Forge/NeoForge 的完整堆栈则写在 crash-reports/crash-*.txt。
//   只看控制台会把这类崩溃误报成“未知退出码”，排障信息丢失。
//
//   这些文件在游戏目录内、由 JVM/游戏进程写出，属于“本地生成、但内容可能被
//   模组 / 被注入的本地库污染”的半可信文本：路径与体积不可信（恶意模组可把一个
//   看似 crash 报告的名字做成指向游戏目录外的符号链接，或写一个数 GiB 的文件做
//   内存/磁盘炸弹）。因此：
//     1. 目录枚举只接受固定前缀/后缀、非目录、非符号链接的条目，并用 PathWithin
//        二次确认解析后仍在崩溃目录内；
//     2. 文件内容一律走 readBoundedFile（Lstat 拒绝符号链接 + 体积上限），超限
//        审计并放弃，绝不整读进内存；
//     3. 行级走 streamBoundedLines（单行字节上限），输出行统一过 sanitizeLogLine
//        / boundCrashContextLine 脱敏与收口，栈帧/原因数量均有硬上限；
//     4. 只按进程启动时间（notBefore）取本局新生成的报告，不读上一局遗留文件。
//
// 本文件只做纯解析与安全收集，不直接弹 UI；调用方（watchGameProcess）在判定
// 崩溃后取出摘要拼进 crashReason。

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

// CrashDumpSummary 是从崩溃产物里提炼出的、可安全展示的结构化摘要。
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

// classifyCrashDump 根据文件头部判定崩溃产物类型。
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

// safeCrashName 只保留崩溃文件名里安全的基名词法，去掉任何目录成分，
// 避免文件名里携带分隔符/盘符（展示与审计用，不参与拼路径）。
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

// cleanCrashLine 统一对崩溃产物里的一行做脱敏与长度收口。
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
