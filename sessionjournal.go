package main

// sessionjournal.go —— 游戏会话台账（session journal）纯函数内核。
//
// 目的：给每次游戏启动/退出留下一条不可膨胀、字段收口的会话记录，供前端展示
// “最近玩过哪些版本、是否崩溃、跑了多久”。数据只落本机 QGL 目录，0600 私有。
// 安全意图：
//   - 版本 ID / 详情等字段一律经 sanitize 收口（长度 + 控制字符），防脏数据写盘；
//   - 单文件有界（readLocalJSONBounded / writePrivateJSONBounded），防撑爆；
//   - 记录上限 MAX_SESSION_JOURNAL_ENTRIES，超出淘汰最旧，防无限增长；
//   - 外部 API 哈希不在本模块出现，本模块不含任何哈希计算（本地台账无需校验）。

import (
	"fmt"
	"path/filepath"
	"strings"
	"time"
)

// SessionOutcome 描述一次会话的结局，供前端分类统计。
const (
	SessionOutcomeRunning    = "running"     // 记录中（尚未退出）
	SessionOutcomeOk         = "ok"          // 正常退出（退出码 0 且窗口出现过）
	SessionOutcomeCrash      = "crash"       // 进程崩溃（退出码非 0 / 命中崩溃关键字）
	SessionOutcomeTimeout    = "timeout"     // 启动超时未出窗口
	SessionOutcomeLaunchFail = "launch-fail" // 启动后立即退出（<3s）
)

// MAX_SESSION_JOURNAL_ENTRIES 是台账单文件最大记录数，超出淘汰最旧。
const MAX_SESSION_JOURNAL_ENTRIES = 200

// sessionJournalMaxBytes 是台账文件的最大字节数（与 jsonLocalDefaultMaxBytes 同量级，
// 显式声明以防默认值被改后本文件失控）。
const sessionJournalMaxBytes = 2 << 20 // 2 MiB

// maxSessionDetailBytes 限制“崩溃详情/备注”字段长度，防止把整段游戏日志写进台账。
const maxSessionDetailBytes = 4096

// SessionRecord 是一次游戏会话的完整记录。
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

// sanitizeSessionRecord 收口单条记录：版本 ID 必须是“不携带控制字符的路径标识”
// （含控制字符直接拒绝，绝不静默改写——改写可能把脏输入映射到别的版本目录），
// 结局必须落在白名单内，详情限制字节数。非法记录返回错误，调用方丢弃而非写盘。
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
