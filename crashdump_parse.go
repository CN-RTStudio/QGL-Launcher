package main

import (
	"strings"
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
