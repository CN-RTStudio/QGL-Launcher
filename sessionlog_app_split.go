package main

import (
	"os"
	"path/filepath"
)

// endGameSessionLogLocked 持有锁时执行结算。
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

// ListSessionLogs 返回会话日志文件列表（新→旧）。
func (a *App) ListSessionLogs(limit int) []sessionLogSummary {
	if limit <= 0 || limit > 100 {
		limit = 100
	}
	return listSessionLogSummaries(a.GetQGLDir(), limit)
}

// GetSessionLogTail 返回指定日志文件尾部最多 n 行（脱敏后）。n<=0 时取 200。
func (a *App) GetSessionLogTail(name string, n int) []sessionLogLine {
	if n <= 0 || n > 500 {
		n = 200
	}
	return sessionLogTail(a.GetQGLDir(), name, n)
}

// GetLatestSessionLogTail 返回最近一份日志的尾部（供"查看上次会话日志"）。
func (a *App) GetLatestSessionLogTail(n int) []sessionLogLine {
	sums := listSessionLogSummaries(a.GetQGLDir(), 1)
	if len(sums) == 0 {
		return nil
	}
	return a.GetSessionLogTail(sums[0].Name, n)
}

// ClearSessionLogs 清空全部会话日志文件，返回删除份数。
func (a *App) ClearSessionLogs() int {
	sums := listSessionLogSummaries(a.GetQGLDir(), 0)
	removed := 0
	for _, s := range sums {
		if err := os.Remove(filepath.Join(a.GetQGLDir(), s.Name)); err == nil {
			removed++
		}
	}
	return removed
}

// IsGameSessionLogActive 报告当前是否有活动会话日志（前端状态指示）。
func (a *App) IsGameSessionLogActive() bool {
	sessionLogStore.mu.Lock()
	defer sessionLogStore.mu.Unlock()
	return sessionLogStore.active
}
