package main

import (
	"os"
	"path/filepath"
	"time"
)

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
