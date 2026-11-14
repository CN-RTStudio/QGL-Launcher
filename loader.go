package main

import (
	_ "embed"
	"fmt"
	"os"
	"path/filepath"
	"time"

)

// ===== 日志功能 =====

// writeLog 将信息写入日志文件（用户可随时查看和复制）
func (a *App) writeLog(format string, args ...interface{}) {
	msg := fmt.Sprintf(format, args...)
	timestamp := time.Now().Format("2006-01-02 15:04:05")
	logLine := fmt.Sprintf("[%s] %s\n", timestamp, msg)

	// 打印到控制台
	fmt.Print(logLine)

	// 写入安装日志（.minecraft 根目录）
	mcDir := a.GetMinecraftDir()
	logPath := filepath.Join(mcDir, "qgl_install.log")
	f, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err == nil {
		f.WriteString(logLine)
		f.Close()
	}

	// 写入启动日志（版本目录下的 QGL\Logs，与 UI 报错内容一致）
	if a.launchLogPath != "" {
		dir := filepath.Dir(a.launchLogPath)
		os.MkdirAll(dir, 0755)
		f2, err2 := os.OpenFile(a.launchLogPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
		if err2 == nil {
			f2.WriteString(logLine)
			f2.Close()
		}
	}
}

// GetFullLog 获取完整日志文本（优先本次启动日志，其次安装日志）
