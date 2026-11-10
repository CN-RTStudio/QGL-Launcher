package main

import (
	"fmt"
	"sync"
	"time"
)

// sessionlog.go —— 游戏会话日志的脱敏持久化内核。
//
// 游戏进程的 stdout/stderr 逐行流在内存里只保留最近 50 行，崩溃排查靠
// dumpCrashContext 临时读文件。本模块把「每局会话的日志」做成可回溯的
// 私有台账：逐行脱敏（控制字符 / 疑似令牌）、环形缓冲限行限字节、会话
// 结束时整体落盘（0600 私有原子写）、按文件数轮转。纯函数层不依赖
// App 与平台 API，可独立单测。

// maxSessionLogLines 单次会话在内存环形缓冲中保留的最大行数。
const maxSessionLogLines = 2000

// maxSessionLogBytes 单次会话日志落盘文件的最大字节数（含 JSON 结构开销）。
const maxSessionLogBytes int64 = 1 << 20 // 1 MiB

// maxSessionLogFiles 保留的会话日志文件份数（超出按最旧轮转删除）。
const maxSessionLogFiles = 24

// maxSessionLogLineBytes 单行日志脱敏后的最大长度。
const maxSessionLogLineBytes = 2048

// sessionLogLine 是落盘文件中的一行记录（时间戳 + 脱敏后的文本）。
type sessionLogLine struct {
	TS   string `json:"ts"`   // RFC3339，日志行到达时间
	Text string `json:"text"` // 脱敏后的日志文本
}

// sessionLogBuffer 是一次会话的日志环形缓冲（纯内存，App 进程内权威）。
type sessionLogBuffer struct {
	lines []sessionLogLine
	bytes int64 // 已占用字节估算（text+ts 之和）
}

// newSessionLogBuffer 返回空缓冲。
func newSessionLogBuffer() sessionLogBuffer {
	return sessionLogBuffer{}
}

type gameSessionLogStore struct {
	mu        sync.Mutex
	active    bool
	versionID string
	startedAt time.Time
	buf       sessionLogBuffer
	lastPath  string // 最近一次落盘文件名（供查询/前端展示）
}

var sessionLogStore = &gameSessionLogStore{}

func (a *App) ensureGameSessionLogDir() error {
	if err := ensurePrivateDir(a.GetQGLDir()); err != nil {
		return fmt.Errorf("初始化会话日志目录失败: %w", err)
	}
	return nil
}
