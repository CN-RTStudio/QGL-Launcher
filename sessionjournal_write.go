package main

import (
	"errors"
	"os"
)

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
