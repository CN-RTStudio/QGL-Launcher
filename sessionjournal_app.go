package main

import (
	"errors"
	"fmt"
	"os"
	"sync"
)

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
