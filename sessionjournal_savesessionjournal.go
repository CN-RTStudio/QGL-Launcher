package main

import (
	"fmt"
)

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
