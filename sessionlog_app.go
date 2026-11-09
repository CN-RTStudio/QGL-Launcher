package main

// sessionlog_app.go —— 会话日志的 App 绑定层。
//
// 与 instancelock / sessionjournal / launchsnapshot 同构：包级单例 store +
// 内存权威缓冲；App 方法只做「把主循环消费的日志行喂进来 / 会话结束时落盘 /
// 供前端查询」。所有持久化复用 sessionlog.go 的纯函数内核与有界私有写。

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// gameSessionLogStore 是当前这一局会话日志的 App 级容器。
// 同一时刻只有一局游戏在运行（实例锁保证），因此单缓冲足够。
type gameSessionLogStore struct {
	mu        sync.Mutex
	active    bool
	versionID string
	startedAt time.Time
	buf       sessionLogBuffer
	lastPath  string // 最近一次落盘文件名（供查询/前端展示）
}

var sessionLogStore = &gameSessionLogStore{}

// ensureGameSessionLogDir 确保会话日志目录（QGL 目录本身）可用。
func (a *App) ensureGameSessionLogDir() error {
	if err := ensurePrivateDir(a.GetQGLDir()); err != nil {
		return fmt.Errorf("初始化会话日志目录失败: %w", err)
	}
	return nil
}

// BeginGameSessionLog 开启一局新会话的日志缓冲（若上一局未结束先落盘）。
func (a *App) BeginGameSessionLog(versionID string) error {
	if err := sanitizePathComponent(versionID); err != nil {
		return fmt.Errorf("无效的版本ID: %w", err)
	}
	if err := a.ensureGameSessionLogDir(); err != nil {
		return err
	}
	sessionLogStore.mu.Lock()
	defer sessionLogStore.mu.Unlock()
	if sessionLogStore.active {
		// 理论上不可能（实例锁已保证单局），但兜底：先结算上一局。
		_ = a.endGameSessionLogLocked()
	}
	sessionLogStore.active = true
	sessionLogStore.versionID = versionID
	sessionLogStore.startedAt = time.Now()
	sessionLogStore.buf = newSessionLogBuffer()
	sessionLogStore.lastPath = ""
	return nil
}

// AppendGameSessionLine 把一行游戏输出喂入当前会话日志（脱敏后缓冲）。
// 无活动会话时静默丢弃（防外部乱序调用产生脏文件）。
func (a *App) AppendGameSessionLine(line string) {
	sessionLogStore.mu.Lock()
	defer sessionLogStore.mu.Unlock()
	if !sessionLogStore.active {
		return
	}
	var accepted bool
	sessionLogStore.buf, accepted = appendSessionLogLine(sessionLogStore.buf, time.Now(), line)
	if !accepted {
		a.writeLog("会话日志已达 %d 字节上限，后续日志行不再保留", maxSessionLogBytes)
	}
}

// EndGameSessionLog 结算当前会话日志：落盘 + 轮转。返回本次落盘文件名。
// 无活动会话时返回空串（不报错）。
func (a *App) EndGameSessionLog() string {
	sessionLogStore.mu.Lock()
	defer sessionLogStore.mu.Unlock()
	return a.endGameSessionLogLocked()
}

// endGameSessionLogLocked 持有锁时执行结算。
func (a *App) endGameSessionLogLocked() string {
	if !sessionLogStore.active {
		return ""
	}
	sessionLogStore.active = false
	if len(sessionLogStore.buf.lines) == 0 {
		return ""
	}
	path := sessionLogFilePathFor(a.GetQGLDir(), sessionLogStore.versionID, sessionLogStore.startedAt)
	if err := persistSessionLog(path, sessionLogStore.buf); err != nil {
		a.writeLog("会话日志落盘失败: %v", err)
		return ""
	}
	sessionLogStore.lastPath = filepath.Base(path)
	rotated := rotateSessionLogs(a.GetQGLDir(), maxSessionLogFiles)
	if rotated > 0 {
		a.writeLog("会话日志轮转清理 %d 个旧文件", rotated)
	}
	return sessionLogStore.lastPath
}

// ListSessionLogs 返回会话日志文件列表（新→旧）。
func (a *App) ListSessionLogs(limit int) []sessionLogSummary {
	if limit <= 0 || limit > 100 {
		limit = 100
	}
	return listSessionLogSummaries(a.GetQGLDir(), limit)
}

// GetSessionLogTail 返回指定日志文件尾部最多 n 行（脱敏后）。n<=0 时取 200。
func (a *App) GetSessionLogTail(name string, n int) []sessionLogLine {
	if n <= 0 || n > 500 {
		n = 200
	}
	return sessionLogTail(a.GetQGLDir(), name, n)
}

// GetLatestSessionLogTail 返回最近一份日志的尾部（供"查看上次会话日志"）。
func (a *App) GetLatestSessionLogTail(n int) []sessionLogLine {
	sums := listSessionLogSummaries(a.GetQGLDir(), 1)
	if len(sums) == 0 {
		return nil
	}
	return a.GetSessionLogTail(sums[0].Name, n)
}

// ClearSessionLogs 清空全部会话日志文件，返回删除份数。
func (a *App) ClearSessionLogs() int {
	sums := listSessionLogSummaries(a.GetQGLDir(), 0)
	removed := 0
	for _, s := range sums {
		if err := os.Remove(filepath.Join(a.GetQGLDir(), s.Name)); err == nil {
			removed++
		}
	}
	return removed
}

// IsGameSessionLogActive 报告当前是否有活动会话日志（前端状态指示）。
func (a *App) IsGameSessionLogActive() bool {
	sessionLogStore.mu.Lock()
	defer sessionLogStore.mu.Unlock()
	return sessionLogStore.active
}
