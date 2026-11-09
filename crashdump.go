package main

import "strings"

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
