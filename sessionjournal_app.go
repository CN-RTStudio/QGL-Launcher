package main

import (
	"errors"
	"fmt"
	"os"
	"sync"
	"time"
)

// sessionJournalStore 内存态：App 进程内权威真相（QGL 目录文件只是持久化副本）。
// 首次访问时从磁盘加载；写盘失败只记录安全事件，不阻塞游戏启动/退出路径。
type sessionJournalStore struct {
	sync.Mutex
	loaded bool
	items  []SessionRecord
}

// defaultSessionJournal 是全局台账存储（与 instanceLocks 同款包级单例）。
var defaultSessionJournal sessionJournalStore

// sessionJournalDir 返回台账目录（QGL 目录）。
func (a *App) sessionJournalDir() string {
	return a.GetQGLDir()
}

// loadSessionJournal 从磁盘加载台账（有界读取）。脏文件按空台账处理，绝不半信任。
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

// saveSessionJournal 原子私有写台账。失败只记审计事件，不向上抛（非关键路径）。
func saveSessionJournal(path string, records []SessionRecord) {
	if err := writePrivateJSONBounded(path, records, sessionJournalMaxBytes); err != nil {
		recordSecurityEvent("session-journal", auditSeverityWarn, auditActionStripped,
			"session-journal", fmt.Sprintf("会话台账写盘失败: %v", err))
	}
}

// ensureSessionJournalLoaded 确保内存台账已从磁盘加载（每个 App 进程一次）。
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

// persistSessionJournal 把内存台账写回磁盘。
func (a *App) persistSessionJournal() {
	journal := &defaultSessionJournal
	journal.Lock()
	defer journal.Unlock()
	saveSessionJournal(sessionJournalFilePath(a.sessionJournalDir()), journal.items)
}

// recordSessionStart 记录一次游戏会话开始（LaunchGame 中 cmd.Start 成功后调用）。
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

// ListSessions 返回最近 N 条会话记录（前端“最近会话”展示；N<=0 时返回全部）。
