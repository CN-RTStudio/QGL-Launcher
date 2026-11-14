package main

import (
	"fmt"
	"sort"
	"time"
)

func (a *App) recordSessionStart(versionID string, pid int) {
	if err := sanitizePathComponent(versionID); err != nil {
		return // 版本 ID 非法不写台账（正常启动路径已前置校验，这里兜底）
	}
	now := time.Now().Format(time.RFC3339)
	rec := SessionRecord{
		VersionID: versionID,
		Pid:       pid,
		StartedAt: now,
		Outcome:   SessionOutcomeRunning,
	}
	if err := sanitizeSessionRecord(&rec); err != nil {
		return
	}
	a.ensureSessionJournalLoaded()
	journal := &defaultSessionJournal
	journal.Lock()
	journal.items = decideSessionAppend(journal.items, rec, MAX_SESSION_JOURNAL_ENTRIES)
	journal.Unlock()
	a.persistSessionJournal()
	recordSecurityEvent("session-journal", auditSeverityInfo, auditActionDetected,
		"session-journal", fmt.Sprintf("游戏会话开始: %s (PID %d)", versionID, pid))
}

// recordSessionEnd 结算一次游戏会话（watchGameProcess 退出路径调用）。
func (a *App) recordSessionEnd(versionID string, pid int, exitCode int, outcome, detail string) {
	if outcome == "" {
		outcome = SessionOutcomeOk
	}
	now := time.Now().Format(time.RFC3339)
	startedAt := ""
	journal := &defaultSessionJournal
	journal.Lock()
	for i := len(journal.items) - 1; i >= 0; i-- {
		rec := &journal.items[i]
		if rec.VersionID == versionID && rec.Pid == pid && rec.Outcome == SessionOutcomeRunning {
			startedAt = rec.StartedAt
			rec.EndedAt = now
			rec.ExitCode = exitCode
			rec.Outcome = outcome
			rec.DurationSec = sessionDurationSec(rec.StartedAt, rec.EndedAt)
			rec.Detail = sanitizeLogLine(detail)
			if len(rec.Detail) > maxSessionDetailBytes {
				rec.Detail = rec.Detail[:maxSessionDetailBytes]
			}
			if err := sanitizeSessionRecord(rec); err != nil {
				// 结算后的记录若非法（例如 outcome 白名单外），回退为未结算运行中，
				// 避免把脏数据写盘。
				rec.Outcome = SessionOutcomeRunning
				rec.EndedAt = ""
				rec.DurationSec = 0
			}
			break
		}
	}
	journal.Unlock()
	a.persistSessionJournal()
	if startedAt != "" {
		recordSecurityEvent("session-journal", auditSeverityInfo, auditActionDetected,
			"session-journal", fmt.Sprintf("游戏会话结束: %s (PID %d) 结局=%s 退出码=%d", versionID, pid, outcome, exitCode))
	}
}

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

type SessionStats struct {
	Total        int     `json:"total"`
	CrashCount   int     `json:"crashCount"`
	OkCount      int     `json:"okCount"`
	RunningCount int     `json:"runningCount"`
	AvgDuration  float64 `json:"avgDurationSec"`
	LastOutcome  string  `json:"lastOutcome"`
}
