package main

import (
	"errors"
	"fmt"
	"os"
	"sync"
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
