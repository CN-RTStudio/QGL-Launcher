package main

import (
	"fmt"
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
