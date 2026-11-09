package main

import (
	"fmt"
	"strings"
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
