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
	"errors"
	"os"
	"path/filepath"
	"strings"
	"time"
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
func parseHsErrCrash(lines []string) CrashDumpSummary {
	s := CrashDumpSummary{Kind: "hs_err"}
	noise := false
	wantFrame := false
	for _, line := range lines {
		trim := strings.TrimSpace(line)

		// 这些段之后是寄存器/内存映射/汇编等噪声，停止收集关键信息。
		if strings.HasPrefix(trim, "siginfo:") || strings.HasPrefix(trim, "Registers:") ||
			strings.HasPrefix(trim, "Stack:") || strings.HasPrefix(trim, "Instructions:") ||
			strings.HasPrefix(trim, "Register to memory mapping") || strings.HasPrefix(trim, "Memory:") ||
			strings.HasPrefix(trim, "vm_info:") || strings.HasPrefix(trim, "---") {
			noise = true
			wantFrame = false
			continue
		}
		if noise {
			continue
		}

		if strings.HasPrefix(trim, "Problematic frame:") {
			wantFrame = true
			continue
		}
		// Problematic frame 的下一条 # 帧（C/J/V/j）。
		if wantFrame && strings.HasPrefix(trim, "#") {
			if frame := hsFrame(trim); frame != "" {
				s.Problematic = frame
			}
			wantFrame = false
			continue
		}

		if strings.HasPrefix(trim, "#") {
			body := strings.TrimSpace(strings.TrimPrefix(trim, "#"))
			if strings.Contains(body, "Internal Error") && s.InternalError == "" {
				s.InternalError = body
				continue
			}
			if strings.Contains(body, "EXCEPTION_") && s.Exception == "" {
				s.Exception = body
				s.Heads = appendUnique(s.Heads, body, 6)
				continue
			}
			if strings.Contains(body, "SIGSEGV") || strings.Contains(body, "SIGABRT") ||
				strings.Contains(body, "SIGILL") || strings.Contains(body, "fatal error") {
				s.Heads = appendUnique(s.Heads, body, 6)
				continue
			}
			if frame := hsFrame(trim); frame != "" && len(s.Frames) < crashDumpMaxFrames {
				s.Frames = append(s.Frames, frame)
			}
		}
	}
	return s
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

// pickLatestDumpEntry 在目录内按文件名前缀/后缀选择本局（modTime >= notBefore）
// 最新的一个非目录、非符号链接条目。返回其完整路径、基名与 mtime。
func pickLatestDumpEntry(dir, prefix, suffix string, notBefore time.Time) (path, name string, mod time.Time, ok bool) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return "", "", time.Time{}, false
	}
	var bestTime time.Time
	for _, entry := range entries {
		// 跳过目录与符号链接（DirEntry.Type 对 symlink 给 ModeSymlink）。
		if entry.IsDir() || entry.Type()&os.ModeSymlink != 0 {
			continue
		}
		fname := entry.Name()
		if !strings.HasPrefix(fname, prefix) || !strings.HasSuffix(fname, suffix) {
			continue
		}
		info, err := entry.Info()
		if err != nil || info.IsDir() {
			continue
		}
		mt := info.ModTime()
		if mt.Before(notBefore) {
			continue
		}
		full := filepath.Join(dir, fname)
		// 二次确认解析结果仍在崩溃目录内，杜绝任何名字携带分隔符的逃逸尝试。
		if resolved, good := PathWithin(dir, full); !good {
			continue
		} else {
			full = resolved
		}
		if !ok || mt.After(bestTime) {
			bestTime = mt
			path, name, mod, ok = full, fname, mt, true
		}
	}
	return path, name, mod, ok
}

// readDumpBounded 通过统一的有界读取载入崩溃产物，超限审计并放弃。
func readDumpBounded(path string) ([]byte, bool) {
	data, err := readBoundedFile(path, crashDumpMaxBytes)
	if err != nil {
		if errors.Is(err, errLocalFileTooLarge) {
			recordSecurityEvent("game-log", auditSeverityWarn, auditActionStripped,
				"crash-dump", "崩溃产物体积超过上限已放弃解析(防内存/磁盘膨胀): "+safeCrashName(path))
			return nil, false
		}
		return nil, false
	}
	return data, true
}

// resolveCrashReportsDir 返回可信的 crash-reports 目录。它必须不是符号链接、
// 且解析后仍位于 gameDir 内——否则若该子目录被预置成指向游戏目录外的链接，
// 直接对其 os.ReadDir 会枚举到外部目录，后续 PathWithin(dir, file) 还会以
// 这个“外部真实目录”为根而误判为合法。
func resolveCrashReportsDir(gameDir string) (string, bool) {
	dir := filepath.Join(gameDir, "crash-reports")
	if IsSymlink(dir) {
		return "", false
	}
	if _, ok := PathWithin(gameDir, dir); !ok {
		return "", false
	}
	return dir, true
}

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
