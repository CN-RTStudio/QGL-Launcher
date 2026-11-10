package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

const (
	SessionOutcomeRunning    = "running"     // 记录中（尚未退出）
	SessionOutcomeOk         = "ok"          // 正常退出（退出码 0 且窗口出现过）
	SessionOutcomeCrash      = "crash"       // 进程崩溃（退出码非 0 / 命中崩溃关键字）
	SessionOutcomeTimeout    = "timeout"     // 启动超时未出窗口
	SessionOutcomeLaunchFail = "launch-fail" // 启动后立即退出（<3s）
)
const MAX_SESSION_JOURNAL_ENTRIES = 200
const sessionJournalMaxBytes = 2 << 20 // 2 MiB
const maxSessionDetailBytes = 4096

type SessionRecord struct {
	VersionID   string `json:"versionId"`
	Pid         int    `json:"pid"`
	StartedAt   string `json:"startedAt"` // RFC3339
	EndedAt     string `json:"endedAt,omitempty"`
	DurationSec int64  `json:"durationSec,omitempty"`
	ExitCode    int    `json:"exitCode,omitempty"`
	Outcome     string `json:"outcome"`
	Detail      string `json:"detail,omitempty"`
}

type sessionJournalStore struct {
	sync.Mutex
	loaded bool
	items  []SessionRecord
}

var defaultSessionJournal sessionJournalStore

func (a *App) sessionJournalDir() string {
	return a.GetQGLDir()
}
func loadSessionJournal(path string) []SessionRecord {
	var records []SessionRecord
	if err := readLocalJSONBounded(path, &records, sessionJournalMaxBytes, "session-journal"); err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			recordSecurityEvent("session-journal", auditSeverityWarn, auditActionStripped,
				"session-journal", fmt.Sprintf("会话台账读取失败，按空台账处理: %v", err))
		}
		return nil
	}
	cleaned := make([]SessionRecord, 0, len(records))
	for _, rec := range records {
		c := sessionRecordCopy(rec)
		if err := sanitizeSessionRecord(&c); err != nil {
			continue // 脏记录整体丢弃
		}
		cleaned = append(cleaned, c)
	}
	return cleaned
}

func saveSessionJournal(path string, records []SessionRecord) {
	if err := writePrivateJSONBounded(path, records, sessionJournalMaxBytes); err != nil {
		recordSecurityEvent("session-journal", auditSeverityWarn, auditActionStripped,
			"session-journal", fmt.Sprintf("会话台账写盘失败: %v", err))
	}
}
func (a *App) ensureSessionJournalLoaded() {
	journal := &defaultSessionJournal
	journal.Lock()
	defer journal.Unlock()
	if journal.loaded {
		return
	}
	journal.items = loadSessionJournal(sessionJournalFilePath(a.sessionJournalDir()))
	journal.loaded = true
}
func (a *App) persistSessionJournal() {
	journal := &defaultSessionJournal
	journal.Lock()
	defer journal.Unlock()
	saveSessionJournal(sessionJournalFilePath(a.sessionJournalDir()), journal.items)
}

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
