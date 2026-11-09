package main

import "strings"

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
