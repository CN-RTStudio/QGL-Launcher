package main

import (
	"time"
)

func (a *App) dumpCrashContext(reason, gameDir string, startTime time.Time) string {
	// 崩溃上下文统一脱敏（用户目录 / QGL 根 / 游戏目录 / JWT / 长十六进制），
	// 防止 hs_err 里的绝对路径与令牌被贴到论坛或经错误通道外发。
	if gameDir == "" {
		return redactCrashText(reason, a.GetQGLDir(), "", a.currentUsername())
	}
	if s, ok := collectLatestCrashDump(gameDir, startTime); ok {
		extra := renderCrashDumpSummary(s)
		combined := extra
		if reason != "" {
			combined = reason + "\n" + extra
		}
		return redactCrashText(combined, a.GetQGLDir(), gameDir, a.currentUsername())
	}
	return redactCrashText(reason, a.GetQGLDir(), gameDir, a.currentUsername())
}
