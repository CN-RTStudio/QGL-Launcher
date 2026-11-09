package main

import (
	"errors"
	"os"
	"sort"
)

func (a *App) ListSessions(limit int) []SessionRecord {
	a.ensureSessionJournalLoaded()
	journal := &defaultSessionJournal
	journal.Lock()
	defer journal.Unlock()
	if limit <= 0 || limit > len(journal.items) {
		limit = len(journal.items)
	}
	out := make([]SessionRecord, 0, limit)
	start := len(journal.items) - limit
	if start < 0 {
		start = 0
	}
	for i := start; i < len(journal.items); i++ {
		out = append(out, sessionRecordCopy(journal.items[i]))
	}
	sort.SliceStable(out, func(x, y int) bool {
		return out[x].StartedAt > out[y].StartedAt
	})
	return out
}

// SessionStats 是一次会话统计快照（前端展示“崩溃率/平均时长”用）。
type SessionStats struct {
	Total        int     `json:"total"`
	CrashCount   int     `json:"crashCount"`
	OkCount      int     `json:"okCount"`
	RunningCount int     `json:"runningCount"`
	AvgDuration  float64 `json:"avgDurationSec"`
	LastOutcome  string  `json:"lastOutcome"`
}

// GetSessionStats 返回会话台账统计。
func (a *App) GetSessionStats() SessionStats {
	a.ensureSessionJournalLoaded()
	journal := &defaultSessionJournal
	journal.Lock()
	defer journal.Unlock()
	stats := SessionStats{Total: len(journal.items)}
	var totalDur int64
	var closed int
	for _, rec := range journal.items {
		switch rec.Outcome {
		case SessionOutcomeCrash, SessionOutcomeTimeout, SessionOutcomeLaunchFail:
			stats.CrashCount++
		case SessionOutcomeOk:
			stats.OkCount++
			closed++
		case SessionOutcomeRunning:
			stats.RunningCount++
		default:
			closed++
		}
		if rec.DurationSec > 0 {
			totalDur += rec.DurationSec
		}
	}
	if len(journal.items) > 0 {
		stats.LastOutcome = journal.items[len(journal.items)-1].Outcome
	}
	if closed > 0 {
		stats.AvgDuration = float64(totalDur) / float64(closed)
	}
	return stats
}

// ClearSessionJournal 清空会话台账（仅本机文件与内存，不删除游戏数据）。
func (a *App) ClearSessionJournal() error {
	journal := &defaultSessionJournal
	journal.Lock()
	journal.items = nil
	journal.loaded = true
	journal.Unlock()
	path := sessionJournalFilePath(a.sessionJournalDir())
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	recordSecurityEvent("session-journal", auditSeverityInfo, auditActionDetected,
		"session-journal", "会话台账已清空")
	return nil
}
