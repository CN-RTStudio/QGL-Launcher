package main

import (
	"fmt"
	"os"
	"path/filepath"
	"time"
)

func (a *App) BeginGameSessionLog(versionID string) error {
	if err := sanitizePathComponent(versionID); err != nil {
		return fmt.Errorf("无效的版本ID: %w", err)
	}
	if err := a.ensureGameSessionLogDir(); err != nil {
		return err
	}
	sessionLogStore.mu.Lock()
	defer sessionLogStore.mu.Unlock()
	if sessionLogStore.active {
		// 理论上不可能（实例锁已保证单局），但兜底：先结算上一局。
		_ = a.endGameSessionLogLocked()
	}
	sessionLogStore.active = true
	sessionLogStore.versionID = versionID
	sessionLogStore.startedAt = time.Now()
	sessionLogStore.buf = newSessionLogBuffer()
	sessionLogStore.lastPath = ""
	return nil
}

// AppendGameSessionLine 把一行游戏输出喂入当前会话日志（脱敏后缓冲）。
// 无活动会话时静默丢弃（防外部乱序调用产生脏文件）。
func (a *App) AppendGameSessionLine(line string) {
	sessionLogStore.mu.Lock()
	defer sessionLogStore.mu.Unlock()
	if !sessionLogStore.active {
		return
	}
	var accepted bool
	sessionLogStore.buf, accepted = appendSessionLogLine(sessionLogStore.buf, time.Now(), line)
	if !accepted {
		a.writeLog("会话日志已达 %d 字节上限，后续日志行不再保留", maxSessionLogBytes)
	}
}

// EndGameSessionLog 结算当前会话日志：落盘 + 轮转。返回本次落盘文件名。
// 无活动会话时返回空串（不报错）。
func (a *App) EndGameSessionLog() string {
	sessionLogStore.mu.Lock()
	defer sessionLogStore.mu.Unlock()
	return a.endGameSessionLogLocked()
}

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

func appendSessionLogLine(buf sessionLogBuffer, ts time.Time, raw string) (sessionLogBuffer, bool) {
	text := sanitizeSessionLogLine(raw, maxSessionLogLineBytes)
	if text == "" {
		return buf, true
	}
	rec := sessionLogLine{TS: ts.Format(time.RFC3339), Text: text}
	est := int64(len(rec.TS) + len(rec.Text) + 4) // +4 近似 JSON 引号/冒号
	if buf.bytes+est > maxSessionLogBytes {
		return buf, false
	}
	buf.lines = append(buf.lines, rec)
	buf.bytes += est
	if len(buf.lines) > maxSessionLogLines {
		dropped := buf.lines[0]
		buf.bytes -= int64(len(dropped.TS) + len(dropped.Text) + 4)
		buf.lines = buf.lines[1:]
	}
	return buf, true
}
