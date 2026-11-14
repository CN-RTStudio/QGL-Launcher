package main

import (
	"context"
	"io"
	"os/exec"
	"path/filepath"
	"sync"

)

// ServerConfig 服务器配置
type ServerConfig struct {
	Name       string `json:"name"`       // 服务器名称
	Version    string `json:"version"`    // MC 版本
	Port       int    `json:"port"`       // 端口
	MaxMemory  int    `json:"maxMemory"`  // 最大内存 MB
	MinMemory  int    `json:"minMemory"`  // 最小内存 MB
	OnlineMode bool   `json:"onlineMode"` // 正版验证
	ServerDir  string `json:"serverDir"`  // 服务器目录
}

// ServerStatus 服务器运行状态
type ServerStatus struct {
	Running bool   `json:"running"`
	Name    string `json:"name"`
	Version string `json:"version"`
	Port    int    `json:"port"`
	PID     int    `json:"pid"`
	Ready   bool   `json:"ready"` // 是否启动完毕
}

// ServerManager 服务器管理器
type ServerManager struct {
	mu        sync.Mutex
	cmd       *exec.Cmd
	stdin     io.WriteCloser
	status    ServerStatus
	logBuffer []string
	ctx       context.Context
	readyCh   chan struct{} // 服务器启动完毕信号
}

var serverMgr ServerManager

// GetServerDir 获取服务器根目录
func (a *App) GetServerDir() string {
	return filepath.Join(a.GetQGLDir(), "server")
}

// GetServerList 获取服务器列表
