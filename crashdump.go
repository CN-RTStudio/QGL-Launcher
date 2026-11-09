package main

//
//
//

import (
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
