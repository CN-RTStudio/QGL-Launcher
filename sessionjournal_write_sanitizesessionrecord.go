package main

import (
	"fmt"
	"path/filepath"
	"strings"
)

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
