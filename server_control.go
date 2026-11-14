package main

import (
	"fmt"
	"time"
)

// StopServer 停止服务器
func (a *App) StopServer() error {
	serverMgr.mu.Lock()
	defer serverMgr.mu.Unlock()
	if !serverMgr.status.Running || serverMgr.stdin == nil {
		return fmt.Errorf("服务器未在运行")
	}
	_, err := serverMgr.stdin.Write([]byte("stop\n"))
	if err != nil {
		if serverMgr.cmd != nil && serverMgr.cmd.Process != nil {
			serverMgr.cmd.Process.Kill()
		}
	}
	return nil
}

// SendServerCommand 向服务器发送命令
func (a *App) SendServerCommand(cmd string) error {
	serverMgr.mu.Lock()
	defer serverMgr.mu.Unlock()
	if !serverMgr.status.Running || serverMgr.stdin == nil {
		return fmt.Errorf("服务器未在运行")
	}
	// 统一走控制台净化内核：拒绝夹带换行 / NUL / 其它控制字符 / 非法 UTF-8 的行，
	// 并限制单行长度，防止渲染层借 stdin 通道做命令注入或打爆服务端日志与存档。
	safeCmd, reason := SanitizeConsoleCommand(cmd)
	if reason != consoleRejectNone {
		recordSecurityEvent(auditCategoryConsole, auditSeverityWarn, auditActionRejected,
			"SendServerCommand", "拒绝非法控制台命令: "+reason)
		return fmt.Errorf("非法的服务器命令: %s", reason)
	}
	// 高速灌入限流：超窗即进入冷却，循环刷 say/fill 等会落盘的命令会被挡下。
	if !serverConsoleGate.allow(time.Now()) {
		recordSecurityEvent(auditCategoryConsole, auditSeverityWarn, auditActionRepeated,
			"SendServerCommand", "控制台命令触发灌入限流，进入冷却")
		return fmt.Errorf("命令发送过于频繁，请稍后再试")
	}
	_, err := serverMgr.stdin.Write([]byte(safeCmd + "\n"))
	return err
}

// GetServerStatus 获取服务器状态
func (a *App) GetServerStatus() ServerStatus {
	serverMgr.mu.Lock()
	defer serverMgr.mu.Unlock()
	return serverMgr.status
}

// GetServerLogs 获取服务器日志
func (a *App) GetServerLogs() []string {
	serverMgr.mu.Lock()
	defer serverMgr.mu.Unlock()
	result := make([]string, len(serverMgr.logBuffer))
	copy(result, serverMgr.logBuffer)
	return result
}
