package main

import (
	"path/filepath"
	"time"
)

// sessionJournalFileName 返回台账文件名（固定单文件）。
func sessionJournalFileName() string {
	return "session-journal.json"
}

// sessionJournalFilePath 返回台账完整路径（QGL 目录下）。
func sessionJournalFilePath(qglDir string) string {
	return filepath.Join(qglDir, sessionJournalFileName())
}

// decideSessionAppend 纯函数：把新记录追加到已有列表，超过上限淘汰最旧。
// 返回新列表（不修改入参，方便单测与并发场景）。
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

// sessionRecordCopy 返回记录的字段拷贝（防外部篡改）。
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
