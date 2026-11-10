package main

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"time"
)

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
