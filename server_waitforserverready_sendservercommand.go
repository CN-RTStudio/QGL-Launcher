package main

import (
	"fmt"

)

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
