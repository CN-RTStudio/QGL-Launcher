package main

import (
	_ "embed"
	"os"
	"path/filepath"

)

func (a *App) GetFullLog() string {
	if a.launchLogPath != "" {
		if data, err := os.ReadFile(a.launchLogPath); err == nil && len(data) > 0 {
			return string(data)
		}
	}
	mcDir := a.GetMinecraftDir()
	if data, err := os.ReadFile(filepath.Join(mcDir, "qgl_install.log")); err == nil {
		return string(data)
	}
	return "暂无日志"
}

// ExportLogTxt 弹出保存对话框，将完整日志导出为 txt，返回保存路径（取消返回空）
