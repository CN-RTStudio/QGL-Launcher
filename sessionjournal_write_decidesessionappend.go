package main

import (
	"time"
)

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
