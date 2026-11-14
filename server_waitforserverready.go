package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

)

func (a *App) WaitForServerReady() error {
	serverMgr.mu.Lock()
	readyCh := serverMgr.readyCh
	if serverMgr.status.Ready {
		serverMgr.mu.Unlock()
		return nil
	}
	serverMgr.mu.Unlock()

	if readyCh == nil {
		return fmt.Errorf("服务器未在运行")
	}

	select {
	case <-readyCh:
		return nil
	case <-time.After(180 * time.Second):
		return fmt.Errorf("服务器启动超时（3分钟）")
	}
}

// StopServer 停止服务器
func (a *App) StopServer() error {
	serverMgr.mu.Lock()
	defer serverMgr.mu.Unlock()

	if !serverMgr.status.Running || serverMgr.stdin == nil {
		return fmt.Errorf("服务器未在运行")
	}

	// 发送 stop 命令
	_, err := serverMgr.stdin.Write([]byte("stop\n"))
	if err != nil {
		// 强制终止
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

	_, err := serverMgr.stdin.Write([]byte(cmd + "\n"))
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
func (a *App) getServerConfig(name string) (*ServerConfig, error) {
	serverDir := a.GetServerDir()
	configPath := filepath.Join(serverDir, name, "QGL", "config.json")

	// 也检查自定义目录
	data, err := os.ReadFile(configPath)
	if err != nil {
		// 尝试从服务器列表中查找
		list, listErr := a.GetServerList()
		if listErr != nil {
			return nil, fmt.Errorf("读取配置失败: %v", err)
		}
		for _, s := range list {
			if s.Name == name {
				return &s, nil
			}
		}
		return nil, fmt.Errorf("找不到服务器 %s", name)
	}

	var cfg ServerConfig
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("解析配置失败: %v", err)
	}
	return &cfg, nil
}

// SetServerOnlineMode 设置服务器正版验证（需要重启）
