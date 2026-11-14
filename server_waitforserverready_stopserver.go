package main

import (
	"fmt"

)

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
