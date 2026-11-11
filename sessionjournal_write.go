package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
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

func sanitizeSessionRecord(rec *SessionRecord) error {
	if rec == nil {
		return fmt.Errorf("nil 会话记录")
	}
	for _, r := range rec.VersionID {
		if r < 0x20 || r == 0x7f {
			return fmt.Errorf("版本ID含控制字符")
		}
	}
	rec.VersionID = strings.TrimSpace(rec.VersionID)
	if rec.VersionID == "" || len(rec.VersionID) > 128 {
		return fmt.Errorf("非法版本ID")
	}
	switch rec.Outcome {
	case SessionOutcomeRunning, SessionOutcomeOk, SessionOutcomeCrash,
		SessionOutcomeTimeout, SessionOutcomeLaunchFail:
	default:
		return fmt.Errorf("非法结局: %s", rec.Outcome)
	}
	rec.Detail = sanitizeLogLine(rec.Detail)
	if len(rec.Detail) > maxSessionDetailBytes {
		rec.Detail = rec.Detail[:maxSessionDetailBytes]
	}
	if rec.Pid <= 0 {
		return fmt.Errorf("非法PID: %d", rec.Pid)
	}
	if rec.StartedAt == "" {
		return fmt.Errorf("缺少开始时间")
	}
	return nil
}

func sessionJournalFileName() string {
	return "session-journal.json"
}
func sessionJournalFilePath(qglDir string) string {
	return filepath.Join(qglDir, sessionJournalFileName())
}
func decideSessionAppend(existing []SessionRecord, next SessionRecord, maxEntries int) []SessionRecord {
	if maxEntries <= 0 {
		maxEntries = MAX_SESSION_JOURNAL_ENTRIES
	}
	nextList := append(append([]SessionRecord{}, existing...), next)
	if len(nextList) > maxEntries {
		nextList = nextList[len(nextList)-maxEntries:]
	}
	return nextList
}

func sessionRecordCopy(rec SessionRecord) SessionRecord {
	return SessionRecord{
		VersionID:   rec.VersionID,
		Pid:         rec.Pid,
		StartedAt:   rec.StartedAt,
		EndedAt:     rec.EndedAt,
		DurationSec: rec.DurationSec,
		ExitCode:    rec.ExitCode,
		Outcome:     rec.Outcome,
		Detail:      rec.Detail,
	}
}

// sessionDurationSec 计算会话时长（秒）；未结束返回 0。
func sessionDurationSec(startedAt, endedAt string) int64 {
	start, err1 := time.Parse(time.RFC3339, startedAt)
	end, err2 := time.Parse(time.RFC3339, endedAt)
	if err1 != nil || err2 != nil {
		return 0
	}
	secs := int64(end.Sub(start) / time.Second)
	if secs < 0 {
		secs = 0
	}
	return secs
}
