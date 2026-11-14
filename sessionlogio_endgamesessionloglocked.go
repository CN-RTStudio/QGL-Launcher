package main

import (
	"path/filepath"
)

func (a *App) endGameSessionLogLocked() string {
	if !sessionLogStore.active {
		return ""
	}
	sessionLogStore.active = false
	if len(sessionLogStore.buf.lines) == 0 {
		return ""
	}
	path := sessionLogFilePathFor(a.GetQGLDir(), sessionLogStore.versionID, sessionLogStore.startedAt)
	if err := persistSessionLog(path, sessionLogStore.buf); err != nil {
		a.writeLog("会话日志落盘失败: %v", err)
		return ""
	}
	sessionLogStore.lastPath = filepath.Base(path)
	rotated := rotateSessionLogs(a.GetQGLDir(), maxSessionLogFiles)
	if rotated > 0 {
		a.writeLog("会话日志轮转清理 %d 个旧文件", rotated)
	}
	return sessionLogStore.lastPath
}
func (a *App) ListSessionLogs(limit int) []sessionLogSummary {
	if limit <= 0 || limit > 100 {
		limit = 100
	}
	return listSessionLogSummaries(a.GetQGLDir(), limit)
}

func (a *App) GetSessionLogTail(name string, n int) []sessionLogLine {
	if n <= 0 || n > 500 {
		n = 200
	}
	return sessionLogTail(a.GetQGLDir(), name, n)
}

// GetLatestSessionLogTail 返回最近一份日志的尾部（供"查看上次会话日志"）。
