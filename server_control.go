package main

import (
	"fmt"
	"path/filepath"
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

// getServerConfig 读取服务器配置
// 安全加固: 校验 name 不含路径遍历字符
// validateLoadedServerConfig 在信任磁盘上的 config.json 之前重新校验全部字段。
//
// 创建时的校验只挡得住前端正常流程；config.json 之后还可能被手工编辑、云盘同步、
// 旧版本写坏或被其他进程篡改。这里的字段（尤其 Version、ServerDir）随后会进入
// 文件路径拼接与 `java -jar <version>-server.jar`，属于代码执行面，因此加载时
// 必须像创建时一样逐项过白名单，任何越界 / 非法值都直接拒绝，绝不带病启动。
func (a *App) validateLoadedServerConfig(cfg *ServerConfig) error {
	if cfg == nil {
		return fmt.Errorf("空服务器配置")
	}
	if sanitizeServerName(cfg.Name) == "" {
		return fmt.Errorf("无效的服务器名称: %q", cfg.Name)
	}
	if err := sanitizePathComponent(cfg.Version); err != nil {
		return fmt.Errorf("无效的版本号: %v", err)
	}
	if !isValidPort(cfg.Port) {
		return fmt.Errorf("无效的端口号: %d", cfg.Port)
	}
	if !isValidMemory(cfg.MaxMemory) || !isValidMemory(cfg.MinMemory) {
		return fmt.Errorf("无效的内存配置")
	}
	if cfg.MinMemory > cfg.MaxMemory {
		return fmt.Errorf("最小内存不能大于最大内存")
	}
	serverRoot := filepath.Clean(a.GetServerDir())
	dir := filepath.Clean(cfg.ServerDir)
	if dir == "" || !filepath.IsAbs(dir) || isPathTraversal(serverRoot, dir) {
		return fmt.Errorf("服务器目录越界或非法: %q", cfg.ServerDir)
	}
	return nil
}

func (a *App) getServerConfig(name string) (*ServerConfig, error) {
	if err := sanitizePathComponent(name); err != nil {
		return nil, fmt.Errorf("无效的服务器名称")
	}
	serverDir := a.GetServerDir()
	configPath := filepath.Join(serverDir, name, "QGL", "config.json")
	var cfg ServerConfig
	if err := readPrivateStoreJSON(configPath, &cfg, "服务器配置"); err != nil {
		list, listErr := a.GetServerList()
		if listErr != nil {
			return nil, fmt.Errorf("读取配置失败: %v", listErr)
		}
		for i := range list {
			if list[i].Name == name {
				return &list[i], nil
			}
		}
		return nil, fmt.Errorf("找不到服务器 %s", name)
	}
	// 加载即校验：拒绝被篡改 / 写坏的配置进入后续 java -jar 执行路径。
	if err := a.validateLoadedServerConfig(&cfg); err != nil {
		return nil, fmt.Errorf("服务器配置不安全: %v", err)
	}
	return &cfg, nil
}
