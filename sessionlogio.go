package main

import (
	"fmt"
	"time"
)

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
